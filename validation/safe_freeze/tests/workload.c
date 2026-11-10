// SPDX-License-Identifier: BSD-2-Clause
// Owned, never-executed hook byte fixtures. Worker code remains unhooked.
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "hook.c"

static HANDLE stop_event;
static volatile LONG ticks;
static DWORD WINAPI worker(void *argument)
{
    (void)argument;
    while (WaitForSingleObject(stop_event, 0) == WAIT_TIMEOUT)
    {
        InterlockedIncrement(&ticks);
        Sleep(1);
    }
    return 0x53;
}
static DWORD WINAPI transient(void *argument) { (void)argument; return 0; }
static DWORD WINAPI churn(void *argument)
{
    (void)argument;
    while (WaitForSingleObject(stop_event, 0) == WAIT_TIMEOUT)
    {
        HANDLE thread = CreateThread(NULL, 0, transient, NULL, 0, NULL);
        if (!thread) return 2;
        if (WaitForSingleObject(thread, 2000) != WAIT_OBJECT_0) return 3;
        if (!CloseHandle(thread)) return 4;
    }
    return 0x53;
}
static void required(BOOL ok, const char *message)
{
    if (!ok) { fprintf(stderr, "FAIL: %s (last_error=%lu)\n", message, GetLastError()); ExitProcess(1); }
}
static unsigned success, failures, cleanup_success, cleanup_failures, unfreeze_attempts;
static void status(MH_STATUS value, const char *message)
{
    if (!strcmp(message,"uninitialize") || !strcmp(message,"direct unfreeze"))
    {
        if(value==MH_OK)++cleanup_success;else ++cleanup_failures;
    }
    if (value != MH_OK) { ++failures; fprintf(stderr, "FAIL: %s status=%d\n", message, value); ExitProcess(2); }
    ++success;
}
static LONGLONG counter(void) { LARGE_INTEGER v; required(QueryPerformanceCounter(&v), "QPC"); return v.QuadPart; }
static DWORD handles(void) { DWORD n; required(GetProcessHandleCount(GetCurrentProcess(), &n), "handle count"); return n; }
static int compare(const void *a, const void *b)
{
    double x=*(const double*)a,y=*(const double*)b;return (x>y)-(x<y);
}
static void summary(const char *name, double *values, unsigned count)
{
    qsort(values,count,sizeof(*values),compare);
    printf("\"%s\":{\"samples\":%u,\"min_us\":%.3f,\"median_us\":%.3f,\"p95_us\":%.3f,\"p99_us\":%.3f,\"max_us\":%.3f}",
        name,count,values[0],count%2?values[count/2]:(values[count/2-1]+values[count/2])/2,
        values[(95*count+99)/100-1],values[(99*count+99)/100-1],values[count-1]);
}
static void freeze_and_measure(LONGLONG *frozen_at, LONGLONG *unfreeze_started, LONGLONG *released_at, DWORD *peak)
{
    FROZEN_THREADS peers;
#if SF_COMPARISON
    status(Freeze(&peers),"direct freeze");
#else
    status(Freeze(&peers,ALL_HOOKS_POS,ACTION_ENABLE),"direct freeze");
#endif
    *frozen_at=counter();
    { DWORD n=handles();if(n>*peak)*peak=n; }
    *unfreeze_started=counter();
    ++unfreeze_attempts;
#if SF_STRICT
    status(Unfreeze(&peers),"direct unfreeze");
#else
    Unfreeze(&peers);
#endif
    *released_at=counter();
}

int main(int argc,char **argv)
{
    enum { METRICS=9, MAX_SAMPLES=1000 };
    const char *names[METRICS]={"initialize","create_batch","single_enable","single_disable",
        "queued_enable","queued_disable","freeze","unfreeze","uninitialize"};
    unsigned threads=argc>1?(unsigned)strtoul(argv[1],NULL,10):4;
    unsigned hooks=argc>2?(unsigned)strtoul(argv[2],NULL,10):11;
    unsigned samples=argc>3?(unsigned)strtoul(argv[3],NULL,10):200;
    unsigned warmup=5,method=argc>4?(unsigned)strtoul(argv[4],NULL,10):0;
    BOOL race=argc>5&&!strcmp(argv[5],"churn");
    BOOL held=argc>5&&!strcmp(argv[5],"held");
    BOOL abort_queue=argc>5&&!strcmp(argv[5],"abort");
    double values[METRICS][MAX_SAMPLES];
    HANDLE peers[65]={0};unsigned i,j;DWORD initial=handles(),peak=initial,after;
    PROCESS_MEMORY_COUNTERS_EX memory,initial_memory,final_memory;SIZE_T peak_working=0,peak_private=0;
    unsigned char *arena;LARGE_INTEGER frequency;
    SYSTEM_INFO info;char cpu[256]="unavailable";DWORD cpu_bytes=sizeof(cpu),type;
    OSVERSIONINFOW os={sizeof(os)};
    typedef LONG (WINAPI *RtlVersion)(OSVERSIONINFOW*);
    RtlVersion version=(RtlVersion)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlGetVersion");
    if(version)version(&os);
    required(threads>=1&&threads<=64&&(hooks==1||hooks==4||hooks==11)&&samples>=1&&samples<=MAX_SAMPLES,"bounded workload arguments");
    required(method<=2,"supported comparison method");
    required(QueryPerformanceFrequency(&frequency),"QPC frequency");
    memset(&initial_memory,0,sizeof initial_memory);initial_memory.cb=sizeof initial_memory;
    required(GetProcessMemoryInfo(GetCurrentProcess(),(PROCESS_MEMORY_COUNTERS*)&initial_memory,sizeof initial_memory),"initial process memory");
    GetNativeSystemInfo(&info);
    RegGetValueA(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0","ProcessorNameString",RRF_RT_REG_SZ,&type,cpu,&cpu_bytes);
    for(i=0;cpu[i];++i)if((unsigned char)cpu[i]<32||cpu[i]=='"'||cpu[i]=='\\')cpu[i]=' ';
    stop_event=CreateEventW(NULL,TRUE,FALSE,NULL);required(stop_event!=NULL,"stop event");
    for(i=0;i<threads;++i){peers[i]=CreateThread(NULL,0,worker,NULL,0,NULL);required(peers[i]!=NULL,"worker creation");}
    if(race){peers[threads]=CreateThread(NULL,0,churn,NULL,0,NULL);required(peers[threads]!=NULL,"churn controller");}
    if(held)required(SuspendThread(peers[0])!=(DWORD)-1,"external suspension");
    arena=VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);required(arena!=NULL,"fixture arena");
    memset(arena,0x90,4096);
    for(i=0;i<hooks;++i){arena[i*128+16]=0xc3;arena[i*128+64]=0xc3;}
    required(FlushInstructionCache(GetCurrentProcess(),arena,4096),"fixture instruction flush");
    for(i=0;i<samples+warmup;++i)
    {
        LONGLONG t[METRICS+1],frozen,unfreeze_started,released,create_started;
        t[0]=counter();status(MH_Initialize(),"initialize");
        t[1]=counter();
#if SF_COMPARISON
        status(MH_SetThreadFreezeMethod((MH_THREAD_FREEZE_METHOD)method),"documented comparison freeze method");
        required(g_threadFreezeMethod==(MH_THREAD_FREEZE_METHOD)method,"comparison method unexpectedly fell back");
#endif
        create_started=counter();
        for(j=0;j<hooks;++j){void *original=NULL;status(MH_CreateHook(arena+j*128,arena+j*128+64,&original),"create");required(original!=NULL,"trampoline");}
        t[2]=counter();
        status(MH_EnableHook(arena),"single enable");t[3]=counter();
        status(MH_DisableHook(arena),"single disable");t[4]=counter();
        for(j=0;j<hooks;++j)status(MH_QueueEnableHook(arena+j*128),"queue enable");
        if(!abort_queue)status(MH_ApplyQueued(),"apply enable");
        t[5]=counter();
        for(j=0;j<hooks;++j)status(MH_QueueDisableHook(arena+j*128),"queue disable");
        status(MH_ApplyQueued(),"apply disable");t[6]=counter();
        freeze_and_measure(&frozen,&unfreeze_started,&released,&peak);
        t[7]=frozen;t[8]=released;
        memset(&memory,0,sizeof memory);memory.cb=sizeof memory;
        required(GetProcessMemoryInfo(GetCurrentProcess(),(PROCESS_MEMORY_COUNTERS*)&memory,sizeof memory),"process memory");
        if(memory.WorkingSetSize>peak_working)peak_working=memory.WorkingSetSize;
        if(memory.PrivateUsage>peak_private)peak_private=memory.PrivateUsage;
        t[9]=counter();status(MH_Uninitialize(),"uninitialize");
        if(i>=warmup){unsigned row=i-warmup;double scale=1000000.0/frequency.QuadPart;
            for(j=0;j<6;++j)values[j][row]=(t[j+1]-t[j])*scale;
            values[1][row]=(t[2]-create_started)*scale;
            values[6][row]=(t[7]-t[6])*scale;values[7][row]=(t[8]-unfreeze_started)*scale;
            values[8][row]=(counter()-t[9])*scale;}
        for(j=0;j<hooks;++j)required(arena[j*128]==0x90,"original target bytes after teardown");
        if(held){DWORD n=SuspendThread(peers[0]);required(n==1,"external suspension was changed");required(ResumeThread(peers[0])==2,"external probe balance");}
    }
    required(VirtualFree(arena,0,MEM_RELEASE),"release fixture");
    if(held)required(ResumeThread(peers[0])==1,"release only external suspension");
    required(SetEvent(stop_event),"stop workers");
    for(i=0;i<threads+(race?1u:0u);++i){DWORD code;required(WaitForSingleObject(peers[i],5000)==WAIT_OBJECT_0,"join worker deadline");required(GetExitCodeThread(peers[i],&code)&&code==0x53,"worker exit");required(CloseHandle(peers[i]),"close worker");}
    required(CloseHandle(stop_event),"close stop event");after=handles();required(after==initial,"residual process handles");
    memset(&final_memory,0,sizeof final_memory);final_memory.cb=sizeof final_memory;
    required(GetProcessMemoryInfo(GetCurrentProcess(),(PROCESS_MEMORY_COUNTERS*)&final_memory,sizeof final_memory),"final process memory");
    printf("{\"variant\":\"%s\",\"method\":%u,\"architecture_bits\":%u,\"configuration\":\"%s\",",SAFE_FREEZE_VARIANT_LABEL,method,(unsigned)(8*sizeof(void*)),SF_CONFIGURATION);
    printf("\"windows_version\":\"%lu.%lu.%lu\",\"cpu\":\"%s\",\"processors\":%lu,",os.dwMajorVersion,os.dwMinorVersion,os.dwBuildNumber,cpu,info.dwNumberOfProcessors);
#if defined(__clang__)
    printf("\"compiler\":\"clang %s\",",__clang_version__);
#elif defined(_MSC_VER)
    printf("\"compiler\":\"MSVC %d\",",_MSC_VER);
#else
    printf("\"compiler\":\"other\",");
#endif
    printf("\"threads\":%u,\"hooks\":%u,\"warmup\":%u,\"samples\":%u,\"scenario\":\"%s\",",threads,hooks,warmup,samples,argc>5?argv[5]:"steady");
    printf("\"reported_cleanup_successes\":%u,\"reported_cleanup_failures\":%u,\"unfreeze_attempts\":%u,\"unfreeze_status_observable\":%s,",cleanup_success,cleanup_failures,unfreeze_attempts,
#if SF_STRICT
        "true"
#else
        "false"
#endif
    );
    printf("\"initial_working_bytes\":%llu,\"initial_private_bytes\":%llu,\"final_working_bytes\":%llu,\"final_private_bytes\":%llu,",(unsigned long long)initial_memory.WorkingSetSize,(unsigned long long)initial_memory.PrivateUsage,(unsigned long long)final_memory.WorkingSetSize,(unsigned long long)final_memory.PrivateUsage);
    printf("\"initial_handles\":%lu,\"observed_peak_handles\":%lu,\"residual_handles\":%ld,\"observed_peak_working_bytes\":%llu,\"observed_peak_private_bytes\":%llu,\"successful_api_operations\":%u,\"failed_api_operations\":%u,\"latencies\":{",initial,peak,(LONG)(after-initial),(unsigned long long)peak_working,(unsigned long long)peak_private,success,failures);
    for(i=0;i<METRICS;++i){if(i)putchar(',');summary(names[i],values[i],samples);}puts("}}");
    return 0;
}
