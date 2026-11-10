// SPDX-License-Identifier: BSD-2-Clause
// Genuine OS threads and engine; no thread/context API interception.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <MinHook.h>
#include "hook.c"

static HANDLE workers_stop, churn_stop, churn_ready;
static volatile LONG workers_ready, transient_created, transient_closed;
static unsigned checks, refused_peer, refused_enumeration, applied;

static void require(BOOL value, const char *message)
{
    ++checks;
    if (!value) { fprintf(stderr,"FAIL: %s (error=%lu)\n",message,GetLastError()); ExitProcess(1); }
}
static DWORD handles(void)
{
    DWORD count;
    require(GetProcessHandleCount(GetCurrentProcess(),&count),"process handle count");
    return count;
}
static DWORD WINAPI active_worker(void *argument)
{
    (void)argument;InterlockedIncrement(&workers_ready);
    return WaitForSingleObject(workers_stop,INFINITE)==WAIT_OBJECT_0?0x53:2;
}
static DWORD WINAPI transient_worker(void *argument) { (void)argument;return 0; }
static DWORD WINAPI churn_worker(void *argument)
{
    BOOL first=TRUE;(void)argument;
    while(WaitForSingleObject(churn_stop,0)==WAIT_TIMEOUT)
    {
        DWORD code;
        HANDLE child=CreateThread(NULL,0,transient_worker,NULL,0,NULL);
        if(!child)return 2;
        InterlockedIncrement(&transient_created);
        if(WaitForSingleObject(child,5000)!=WAIT_OBJECT_0)return 3;
        if(!GetExitCodeThread(child,&code)||code!=0)return 4;
        if(!CloseHandle(child))return 5;
        InterlockedIncrement(&transient_closed);
        if(first){if(!SetEvent(churn_ready))return 6;first=FALSE;}
    }
    return 0x53;
}
static void state(BOOL physical,BOOL queued)
{
    UINT i;
    require(g_hooks.size==11,"all eleven hook owners remain registered");
    for(i=0;i<g_hooks.size;++i)
    {
        const HOOK_ENTRY *hook=&g_hooks.pItems[i];
        const unsigned char *target=hook->pTarget;
        require(hook->isEnabled==physical,"physical flag changed unexpectedly");
        require(hook->queueEnable==queued,"queued intent changed unexpectedly");
        if(physical)
        {
            INT32 distance;DWORD_PTR destination;
            require(target[0]==0xe9,"enabled target opcode");
            memcpy(&distance,target+1,sizeof distance);
            destination=(DWORD_PTR)target+5+(INT_PTR)distance;
            require(destination==(DWORD_PTR)hook->pDetour,"enabled target destination");
        }
        else
            require(memcmp(target,"\x90\x90\x90\x90\x90",5)==0,"unpatched target bytes changed");
    }
}
static BOOL apply(BOOL before,BOOL wanted,unsigned cycle,const char *phase)
{
    MH_STATUS result=MH_ApplyQueued();
    if(result==MH_OK)
    {
        state(wanted,wanted);
        require(!HasRetainedThreadOwnership(),"successful apply retained peer ownership");
        ++applied;return TRUE;
    }
    // A strict refusal is expected under birth/exit races only when preparation
    // has made no physical patch, preserved queued intent and retired peers.
    // Do not accept partial patches, unresolved cleanup or arbitrary failures.
    require(result==MH_ERROR_MEMORY_PROTECT||result==MH_UNKNOWN,"unexpected race status");
    state(before,wanted);
    require(!HasRetainedThreadOwnership(),"race refusal left unresolved physical peer ownership");
    if(result==MH_ERROR_MEMORY_PROTECT)++refused_peer;else ++refused_enumeration;
    fprintf(stderr,"STRICT_REFUSAL cycle=%u phase=%s status=%d unchanged_bytes=1 queued_intent_preserved=1 peers_drained=1\n",cycle,phase,result);
    return FALSE;
}
int main(int argc,char **argv)
{
    unsigned cycles=argc>1?(unsigned)strtoul(argv[1],NULL,10):200,i,j;
    HANDLE workers[16];unsigned char *arena;
    DWORD initial,owned,started;
    puts("CHURN_CONTRACT: genuine threads; safe refusals are logged and rolled back, never hidden");
    require(cycles>=1&&cycles<=1000,"bounded transaction count");
    initial=handles();
    workers_stop=CreateEventW(NULL,TRUE,FALSE,NULL);require(workers_stop!=NULL,"worker stop event");
    for(i=0;i<16;++i){workers[i]=CreateThread(NULL,0,active_worker,NULL,0,NULL);require(workers[i]!=NULL,"create active worker");}
    started=GetTickCount();
    while(workers_ready!=16&&GetTickCount()-started<5000)Sleep(1);
    require(workers_ready==16,"all workers completed startup before first freeze");
    owned=handles();
    arena=VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);require(arena!=NULL,"owned hook arena");
    memset(arena,0x90,4096);
    for(i=0;i<11;++i){arena[i*128+16]=0xc3;arena[i*128+64]=0xc3;}
    require(FlushInstructionCache(GetCurrentProcess(),arena,4096),"flush fixture bytes");
    for(i=0;i<cycles;++i)
    {
        HANDLE churn;DWORD code;
        require(MH_Initialize()==MH_OK,"initialize next independent transaction");
        require(ResolveNtGetNextThread()!=NULL,"strict Nt API available, with no fallback");
        for(j=0;j<11;++j){void *original=NULL;require(MH_CreateHook(arena+j*128,arena+j*128+64,&original)==MH_OK&&original!=NULL,"create transaction hook owner");}
        state(FALSE,FALSE);
        churn_stop=CreateEventW(NULL,TRUE,FALSE,NULL);churn_ready=CreateEventW(NULL,TRUE,FALSE,NULL);
        require(churn_stop&&churn_ready,"owned churn events");
        churn=CreateThread(NULL,0,churn_worker,NULL,0,NULL);require(churn!=NULL,"owned churn controller");
        require(WaitForSingleObject(churn_ready,5000)==WAIT_OBJECT_0,"at least one transient created and joined before racing");
        require(MH_QueueEnableHook(MH_ALL_HOOKS)==MH_OK,"queue enable under churn");
        if(apply(FALSE,TRUE,i,"enable"))
        {
            require(MH_QueueDisableHook(MH_ALL_HOOKS)==MH_OK,"queue disable under churn");
            (void)apply(TRUE,FALSE,i,"disable");
        }
        // A refusal ends this transaction. Quiesce churn, explicitly cancel
        // pending intent and prove rollback before starting a new transaction.
        require(SetEvent(churn_stop),"quiesce thread creation before rollback");
        require(WaitForSingleObject(churn,5000)==WAIT_OBJECT_0,"join churn within deadline");
        require(GetExitCodeThread(churn,&code)&&code==0x53,"churn created/joined/closed every child");
        require(CloseHandle(churn)&&CloseHandle(churn_ready)&&CloseHandle(churn_stop),"close exact churn owners");
        require(MH_QueueDisableHook(MH_ALL_HOOKS)==MH_OK,"cancel any pending queued activation");
        require(MH_DisableHook(MH_ALL_HOOKS)==MH_OK,"rollback against stable handshaken workers");
        state(FALSE,FALSE);
        require(!HasRetainedThreadOwnership(),"rollback completed physical peer cleanup");
        for(j=0;j<11;++j)require(MH_RemoveHook(arena+j*128)==MH_OK,"remove only after rollback and peer drain");
        require(MH_Uninitialize()==MH_OK&&g_hHeap==NULL,"retire exact transaction heap");
        require(handles()==owned,"no engine/churn handle growth between independent transactions");
    }
    require(transient_created==transient_closed&&transient_created>=(LONG)cycles,"every transient child physically closed");
    require(VirtualFree(arena,0,MEM_RELEASE),"free arena after engine retirement");
    require(SetEvent(workers_stop),"stop stable workers");
    for(i=0;i<16;++i){DWORD code;require(WaitForSingleObject(workers[i],5000)==WAIT_OBJECT_0,"join stable worker");require(GetExitCodeThread(workers[i],&code)&&code==0x53,"stable worker exit");require(CloseHandle(workers[i]),"close stable worker handle");}
    require(CloseHandle(workers_stop),"close stable stop event");
    require(handles()==initial,"zero residual owned process handles");
    printf("{\"variant\":\"candidate_strict\",\"scenario\":\"thread_churn_failure_atomic_preparation\",\"cycles\":%u,\"checks\":%u,\"applied_transitions\":%u,\"logged_peer_refusals\":%u,\"logged_enumeration_refusals\":%u,\"transients_created\":%ld,\"transients_closed\":%ld,\"residual_handles\":0,\"all_transactions_rolled_back\":true}\n",cycles,checks,applied,refused_peer,refused_enumeration,transient_created,transient_closed);
    return 0;
}
