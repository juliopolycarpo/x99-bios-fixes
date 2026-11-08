; IA32 trampoline for the existing ensure_no_pending_transaction entry.
; Copy its displaced prologue, reject uncertain workers before any original
; callback/bus checks, then resume the existing gate. No new relocations:
; code transfers are relative, and context offsets are not image addresses.
BITS 32
ORG GUARD_VA

    push ebp
    mov ebp, esp
    sub esp, 24
    push eax
    push ecx
    push edx
    mov edx, [ebp+8]
    movzx ecx, byte [edx+0x43d05]
    cmp ecx, 4
    jae unsafe_workers
    mov eax, 1
    shl eax, cl
    cmp [edx+0x220fc], eax
    jne unsafe_workers
    cmp byte [edx+0x22108], 0
    jne unsafe_workers
    pop edx
    pop ecx
    pop eax
    jmp RESUME_VA

unsafe_workers:
    push 1
    call HALT_FN
    ud2
