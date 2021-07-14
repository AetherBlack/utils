BITS 64
    GLOBAL _start
section .text

_start:
    ;; clean register an go to end
    xor rax, rax
    xor rdi, rdi
    xor rsi, rsi
    xor rdx, rdx
    jmp end

exit:
    xor rax, rax
    mov al, 0x3c
    xor rdi, rdi
    syscall

read:
    ;; read(0x3, *buffer, 0x1)
    xor rax, rax    ; read syscall
    push rax        ; clean stack

    mov dil, 0x3    ; file descriptor
    sub rsp, 0x1    ; buffer
    lea rsi, [rsp]  ; *buffer
    xor rdx, rdx    ; count
    mov dl, 0x1     ; count
    syscall

    xor rdi, rdi    ; clean
    cmp rax, rdi    ; check value
    je exit         ; if EOF exit

    ;; write(0x1, *buffer, 0x1)
    xor rax, rax    ; clean
    xor rdi, rdi    ; clean
    mov al, 0x1     ; write
    mov dil, 0x1    ; count
    syscall

    add rsp, 0x1    ; *buffer
    jmp read        ; loop

end:
    ;; call read
    call read
