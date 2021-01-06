BITS 64
        GLOBAL _start
section .text

_start:
        xor rax, rax
        push rax
        push  byte '.'

        ;; sys_open(".", 0, 0)
        ;mov rax, 0x2   ; open syscall
        ;mov rdi, file   ; filename
        ;mov rsi, 0x0   ; flags
        ;mov rdx, 0x0   ; mode
        ;syscall

        ;; openat(AT_FDCWD, ".", 0, 0)
        mov rax, 0x101  ; openat syscall
        mov rdi, -0x64  ; AT_FDCWD current working directory
        mov rsi, file   ; filename
        mov rdx, 0x0    ; flags
        mov r10, 0x0    ; mode
        syscall

        ;;  getdents(fd,esp,0x3210)
        mov rdi,rax     ; file descriptor returned by open syscall
        mov rax, 0x4e   ; getdents syscall
        mov rdx, 0x3210 ; count
        sub rsp, rdx    ; ?
        mov rsi, rsp    ; struct dirent
        syscall

        xchg rax,rdx    ; rax, rdx = rdx, rax

        ;; write(1, rsp, rdx)
        mov rax, 0x1    ; write syscall
        mov rdi, 0x1    ; stdout

        mov rsi, rsp    ; strings to write
        ; rdx has length of the strings rsp
        syscall


        ;; exit(0)
        mov rax, 0x3c   ; exit syscall
        mov rdi, 0x0    ; 0 status code
        syscall

section .data
file: db '.', 0x0
