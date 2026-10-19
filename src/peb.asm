.code
; PVOID GetPeb(VOID)
GetPeb PROC
    mov rax, gs:[60h]
    ret
GetPeb ENDP
END