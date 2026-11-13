// SPDX-License-Identifier: BSD-2-Clause
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "trampoline.h"

#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

static unsigned failures;

static void require(BOOL condition, const char *message)
{
    if (!condition)
    {
        ++failures;
        fprintf(stderr, "FAIL: %s\n", message);
    }
}

BOOL IsExecutableAddress(LPVOID address)
{
    MEMORY_BASIC_INFORMATION mi;
    return VirtualQuery(address, &mi, sizeof(mi))
        && mi.State == MEM_COMMIT
        && (mi.Protect & PAGE_EXECUTE_FLAGS) != 0;
}

static BYTE *allocate(SIZE_T size)
{
    BYTE *memory = (BYTE *)VirtualAlloc(
        NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    require(memory != NULL, "allocate test memory");
    return memory;
}

static void test_rip_relative_range(void)
{
    BYTE *block = allocate(4096);
    BYTE *trampoline;
    BYTE *target;
    TRAMPOLINE ct;
    INT32 displacement;
    INT32 relocated;
    INT64 expected;

    if (block == NULL)
        return;

    trampoline = block + 64;
    target = block + 512;
    memset(&ct, 0, sizeof(ct));
    memset(target, 0x90, 32);
    target[0] = 0x48;
    target[1] = 0x8B;
    target[2] = 0x05;
    displacement = INT32_MAX;
    memcpy(target + 3, &displacement, sizeof(displacement));
    target[7] = 0xC3;
    ct.pTarget = target;
    ct.pDetour = block + 1024;
    ct.pTrampoline = trampoline;
    require(!CreateTrampolineFunction(&ct),
        "reject positive RIP-relative displacement overflow");

    trampoline = block + 512;
    target = block + 64;
    memset(&ct, 0, sizeof(ct));
    memset(target, 0x90, 32);
    target[0] = 0x48;
    target[1] = 0x8B;
    target[2] = 0x05;
    displacement = INT32_MIN;
    memcpy(target + 3, &displacement, sizeof(displacement));
    target[7] = 0xC3;
    ct.pTarget = target;
    ct.pDetour = block + 1024;
    ct.pTrampoline = trampoline;
    require(!CreateTrampolineFunction(&ct),
        "reject negative RIP-relative displacement overflow");

    trampoline = block + 512;
    target = block + 64;
    memset(&ct, 0, sizeof(ct));
    memset(target, 0x90, 32);
    target[0] = 0x48;
    target[1] = 0x8B;
    target[2] = 0x05;
    displacement = 128;
    memcpy(target + 3, &displacement, sizeof(displacement));
    target[7] = 0xC3;
    ct.pTarget = target;
    ct.pDetour = block + 1024;
    ct.pTrampoline = trampoline;
    require(CreateTrampolineFunction(&ct),
        "accept in-range RIP-relative displacement");
    memcpy(&relocated, trampoline + 3, sizeof(relocated));
    expected = (INT64)(target + 7) + displacement;
    require((INT64)(trampoline + 7) + relocated == expected,
        "preserve in-range RIP-relative effective address");

    trampoline = block + 64;
    target = block + 512;
    memset(&ct, 0, sizeof(ct));
    memset(target, 0x90, 32);
    target[0] = 0x67;
    target[1] = 0x48;
    target[2] = 0x8B;
    target[3] = 0x05;
    displacement = INT32_MAX;
    memcpy(target + 4, &displacement, sizeof(displacement));
    target[8] = 0xC3;
    ct.pTarget = target;
    ct.pDetour = block + 1024;
    ct.pTrampoline = trampoline;
    require(CreateTrampolineFunction(&ct),
        "accept wrapping EIP-relative displacement");
    memcpy(&relocated, trampoline + 4, sizeof(relocated));
    require((UINT32)((ULONG_PTR)(trampoline + 8) + (UINT32)relocated)
            == (UINT32)((ULONG_PTR)(target + 8) + (UINT32)displacement),
        "preserve EIP-relative effective address modulo 32 bits");

    VirtualFree(block, 0, MEM_RELEASE);
}

static void test_vex_classification(void)
{
    static const BYTE instruction[] = { 0xC4, 0xE2, 0x6D, 0x8C, 0x08 };
    BYTE *block = allocate(4096);
    BYTE *target;
    BYTE *trampoline;
    TRAMPOLINE ct;

    if (block == NULL)
        return;

    target = block + 64;
    trampoline = block + 512;
    memset(&ct, 0, sizeof(ct));
    memset(target, 0x90, 32);
    memcpy(target, instruction, sizeof(instruction));
    target[sizeof(instruction)] = 0xC3;
    ct.pTarget = target;
    ct.pDetour = block + 1024;
    ct.pTrampoline = trampoline;
    require(CreateTrampolineFunction(&ct), "create VEX trampoline");
    require(memcmp(trampoline, instruction, sizeof(instruction)) == 0,
        "copy VEX opcode ending in 8C instead of treating it as Jcc");

    VirtualFree(block, 0, MEM_RELEASE);
}

static void test_page_boundary(void)
{
    SYSTEM_INFO systemInfo;
    BYTE *region;
    BYTE *firstPage;
    BYTE *trampoline;
    BYTE *target;
    TRAMPOLINE ct;

    GetSystemInfo(&systemInfo);
    region = (BYTE *)VirtualAlloc(
        NULL, systemInfo.dwPageSize * 2, MEM_RESERVE, PAGE_NOACCESS);
    require(region != NULL, "reserve boundary test pages");
    if (region == NULL)
        return;

    firstPage = (BYTE *)VirtualAlloc(
        region, systemInfo.dwPageSize, MEM_COMMIT, PAGE_READWRITE);
    trampoline = allocate(4096);
    if (firstPage == NULL || trampoline == NULL)
    {
        require(firstPage != NULL, "commit first boundary test page");
        if (trampoline != NULL)
            VirtualFree(trampoline, 0, MEM_RELEASE);
        VirtualFree(region, 0, MEM_RELEASE);
        return;
    }

    memset(firstPage, 0x90, systemInfo.dwPageSize);
    target = firstPage + systemInfo.dwPageSize - 1;
    *target = 0xC3;
    memset(&ct, 0, sizeof(ct));
    ct.pTarget = target;
    ct.pDetour = firstPage;
    ct.pTrampoline = trampoline;
    require(!CreateTrampolineFunction(&ct),
        "reject an unreadable trailing page without an access violation");

    VirtualFree(trampoline, 0, MEM_RELEASE);
    VirtualFree(region, 0, MEM_RELEASE);
}

int main(void)
{
    test_rip_relative_range();
    test_vex_classification();
    test_page_boundary();
    if (failures != 0)
    {
        fprintf(stderr, "%u hardening checks failed\n", failures);
        return 1;
    }
    puts("x64 trampoline hardening checks passed");
    return 0;
}
