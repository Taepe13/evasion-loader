@echo off
cd /d "%~dp0"

echo [*] Building evasion-loader...

set VCVARS=
for %%P in (
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
) do (
    if exist %%P set VCVARS=%%P
)

if not defined VCVARS (
    echo [!] vcvars64.bat not found.
    pause
    exit /b 1
)

call %VCVARS% >nul

echo [*] Assembling syscalls...
ml64.exe /c /Fo syscalls-asm.obj syscalls\syscalls-asm.x64.asm
if errorlevel 1 goto :masm_syscalls_failed

echo [*] Assembling peb.asm...
ml64.exe /c /Fo peb.obj src\peb.asm
if errorlevel 1 goto :masm_peb_failed

echo [*] Compiling C code...
cl src\*.c syscalls\syscalls.c syscalls-asm.obj peb.obj /Fe:evasion-loader.exe /Zi /EHsc /D_UNICODE /DUNICODE
if errorlevel 1 goto :cl_failed

echo [+] Build successful: evasion-loader.exe
pause
exit /b 0

:masm_syscalls_failed
echo [!] MASM failed (syscalls)
pause
exit /b 1

:masm_peb_failed
echo [!] MASM failed (peb)
pause
exit /b 1

:cl_failed
echo [!] Build failed (cl/link)
pause
exit /b 1