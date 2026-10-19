# evasion-loader (C)

Shellcode loader featuring NTDLL unhooking and indirect system calls (SysWhispers).

## Features

  * **Evasion techniques:**
    * `Ntdll Unhooking (Disk Sync)` - Restores the original `.text` section of `ntdll.dll` by reading a fresh copy from the disk. (`C:\Windows\System32\ntdll.dll`). This completely removes user-mode EDR/AV hooks. Uses a safe minimum-size calculation to prevent Access Violations.
    * `Indirect Syscalls` - Uses SysWhispers (Jumper technique) to dynamically resolve the address of the `syscall` instruction inside `ntdll.dll` and jump to it.
    * `Payload Deobfuscation` - IPv4 string deobfuscation (via `RtlIpv4StringToAddressA`) and simple XOR decryption to hide the shellcode from static analysis.
  * **Inline Assembly (MASM)** - Custom `GetPeb` stub written in x64 assembly.
  * **x64 Windows** - Tested on Windows 10/11.
  * **MSVC** - Builds with Visual Studio Build Tools 2022.

## Project Structure

    evasion-loader/
    ├── src/
    │   ├── main.c           # CLI entry point (loader execution flow)
    │   ├── payload.c        # Obfuscated shellcode (IPv4 strings) and XOR key
    │   ├── payload.h        # Payload definitions
    │   ├── unhook.c         # NTDLL unhooking logic (disk sync)
    │   ├── unhook.h
    │   └── peb.asm          # MASM stub for GetPeb (bypasses intrin.h)
    ├── syscalls/
    │   ├── syscalls.c       # SysWhispers hash resolution and table population
    │   ├── syscalls.h
    │   └── syscalls-asm.x64.asm # MASM stubs for indirect syscalls
    ├── build.bat            # Build script (MASM + MSVC)
    └── README.md

## How it works

**Step 1: NTDLL Unhooking (Disk Sync)**  
Reads a clean copy of `ntdll.dll` from `C:\Windows\System32\`. It locates the `.text` section, maps the clean version, and overwrites the hooked bytes in memory. Uses a safe minimum-size calculation to avoid Access Violations.

**Step 2: Payload Deobfuscation**  
Shellcode is stored as IPv4 strings. The loader converts them back to raw bytes via `RtlIpv4StringToAddressA`, then applies a single-byte XOR decryption (`0xAA`).

**Step 3: Indirect System Calls (SysWhispers Jumper)**  
Bypasses user-mode hooks by dynamically resolving function hashes. Instead of hardcoded SSNs (Direct Syscalls), it finds the `syscall; ret` instructions inside the clean `ntdll.dll` memory and jumps directly to them.

**Step 4: Execution**  
Allocates `PAGE_READWRITE` memory, writes the payload, changes protection to `PAGE_EXECUTE_READ` (RX), and executes via `NtCreateThreadEx`. Waits for the thread to finish.

## Requirements

  * Windows 10/11 (x64)
  * MSVC (Visual Studio Build Tools 2022)
  * MASM (included with MSVC)

## Build / Usage
```cmd
build.bat
evasion-loader.exe
```
