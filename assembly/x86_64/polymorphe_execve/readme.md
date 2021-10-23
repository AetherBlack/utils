# polymorphe_execve

Polymorphe shellcode to bypass some check like the presence of `/bin/sh` or `syscall` instruction.

## Compile

```nasm
nasm -f elf64 polymorphe_execve.asm  -o polymorphe_execve.o && gcc polymorphe_execve.o -o polymorphe_execve -fno-stack-protector -z execstack -no-pie
```
