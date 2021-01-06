# ls

ls in asm.

Use strings after the command to correct output.

```bash
$ ./main | strings
main
main.asm
main.o
main.shellcode
password
utils
```

## Compile

```bash
nasm -f elf64 main.asm -o main.o && ld main.o -o main
```
