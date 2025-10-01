.data
currentHash     dd  0
returnAddress   dq  0
syscallNumber   dd  0
syscallAddress  dq  0

.code
EXTERN SW2_GetSyscallNumber: PROC
EXTERN SW2_GetRandomSyscallAddress: PROC
    
WhisperMain PROC
    pop rax
    mov [rsp+ 8], rcx                       ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    nop
    nop
    mov ecx, currentHash
    nop
    nop
    nop
    call SW2_GetSyscallNumber
    nop
    nop
    mov dword ptr [syscallNumber], eax      ; Save the syscall number
    xor rcx, rcx
    nop
    nop
    call SW2_GetRandomSyscallAddress        ; Get a random syscall address
    nop
    nop
    mov qword ptr [syscallAddress], rax     ; Save the random syscall address
    xor rax, rax
    nop
    nop
    mov eax, syscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]                       ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    nop
    nop
    nop
    mov r10, rcx
    nop
    nop
    pop qword ptr [returnAddress]           ; Save the original return address
    nop
    nop
    call qword ptr [syscallAddress]         ; Call the random syscall instruction
    push qword ptr [returnAddress]          ; Restore the original return address
    ret
WhisperMain ENDP

NtAllocateVirtualMemory PROC
    mov currentHash, 00E991418h    ; Load function hash into global variable.
    nop
    nop
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemory ENDP

NtProtectVirtualMemory PROC
    mov currentHash, 00D9F213Bh    ; Load function hash into global variable.
    nop
    nop
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtProtectVirtualMemory ENDP

end