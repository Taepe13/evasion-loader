#pragma once

#include <Windows.h>

PVOID GetNtdllBaseAddress(void);
PVOID ReadNtDllFromDisk(SIZE_T* pSize);
BOOL UnhookNtdll(void);
BOOL IsFunctionIsHooked(PVOID pFunction);
extern PVOID GetPeb(void);