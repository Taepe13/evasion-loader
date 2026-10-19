#include "unhook.h"
#include <stdio.h>
#include <string.h>
#include <winternl.h>

PVOID GetNtdllBaseAddress(void)
{
    PPEB pPeb = (PPEB)GetPeb(); // PEB at address GS:[0x60]
    if (!pPeb) return NULL;

    PLIST_ENTRY pList = pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink;
    PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pList - 0x10); // InMemoryOrderLinks has a offset 0x10 from entry_table
    return pEntry->DllBase;
}

PVOID ReadNtDllFromDisk(SIZE_T* pSize)
{
    char winPath[MAX_PATH] = { 0 };
    char ntdllPath[MAX_PATH] = { 0 };

    if (GetWindowsDirectoryA(winPath, MAX_PATH) == 0) return NULL;

    snprintf(ntdllPath, MAX_PATH, "%s\\System32\\ntdll.dll", winPath);

    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD fileSize = GetFileSize(hFile, NULL);

    PVOID pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
    if (!pBuffer)
    {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, pBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize)
    {
        HeapFree(GetProcessHeap(), 0, pBuffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *pSize = fileSize;
    return pBuffer;
    
}

BOOL IsFunctionIsHooked(PVOID pFunction)
{
    if (!pFunction) return FALSE;

    BYTE* pBytes = (BYTE*)pFunction;

    // Functions of ntdll starting with:
    // 4C 8B D1 - mov r10, rcx
    // B8 XX XX XX XX - mov eax, SSN
    if (pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1 && pBytes[3] == 0xB8) // function is unhooked
    {
        return FALSE;
    }
    return TRUE;
}

BOOL UnhookNtdll(void)
{
    PVOID pLocalNtdll = GetNtdllBaseAddress();
    if (!pLocalNtdll)
    {
        printf("[!] Failed to get ntdll base\n");
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pLocalNtdll;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER pSecLocal = IMAGE_FIRST_SECTION(pNt);
    PIMAGE_SECTION_HEADER pTextLocal = NULL;

    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        if (strncmp((const char*)pSecLocal[i].Name, ".text", 8) == 0)
        {
            pTextLocal = &pSecLocal[i];
            break;
        }
    }
    if (!pTextLocal) return FALSE;

    PVOID pLocalText = (PBYTE)pLocalNtdll + pTextLocal->VirtualAddress;
    SIZE_T sLocalText = pTextLocal->Misc.VirtualSize;

    SIZE_T sCleanNtdll = 0;
    PVOID pCleanNtdll = ReadNtDllFromDisk(&sCleanNtdll);
    if (!pCleanNtdll) return FALSE;

    PIMAGE_DOS_HEADER pCleanDos = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pCleanNt = (PIMAGE_NT_HEADERS)((PBYTE)pCleanNtdll + pCleanDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSecClean = IMAGE_FIRST_SECTION(pCleanNt);
    PIMAGE_SECTION_HEADER pTextClean = NULL;
    for (int i = 0; i < pCleanNt->FileHeader.NumberOfSections; i++)
    {
        if (strncmp((const char*)pSecClean[i].Name, ".text", 8) == 0)
        {
            pTextClean = &pSecClean[i];
            break;
        }
    }

    if (!pTextClean)
    {
        HeapFree(GetProcessHeap(), 0, pCleanNtdll);
        return FALSE;
    }

    PVOID pCleanText = (PBYTE)pCleanNtdll + pTextClean->PointerToRawData;
    SIZE_T sCleanText = pTextClean->SizeOfRawData;


    SIZE_T sCopySize = (sLocalText < sCleanText) ? sLocalText : sCleanText; // Saving the min size
    DWORD oldProtect = 0;
    if (!VirtualProtect(pLocalText, sCopySize, PAGE_EXECUTE_WRITECOPY, &oldProtect))
    {
        HeapFree(GetProcessHeap(), 0, pCleanNtdll);
        return FALSE;
    }

    memcpy(pLocalText, pCleanText, sCopySize);

    DWORD old_protect = 0;
    VirtualProtect(pLocalText, sCopySize, oldProtect, &old_protect);

    HeapFree(GetProcessHeap(), 0, pCleanNtdll);
    return TRUE;
}