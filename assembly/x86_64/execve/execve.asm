BITS 64
    GLOBAL _start
section .text

_start:
    ;; execve("//bin/sh", 0, 0)
    xor rax, rax    ; clean
    push rax        ; Null byte
    mov al, 0x3b    ; execve
    mov rdi, 0x68732f6e69622f2f ; n/sh//bi
    push rdi        ; //bin/sh
    mov rdi, rsp    ; //bin/sh
    xor rsi, rsi    ; NULL
    xor rdx, rdx    ; NULL
    syscall
