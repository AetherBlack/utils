all:
	nasm -f elf64 polymorphe_execve.asm  -o polymorphe_execve.o && gcc polymorphe_execve.o -o polymorphe_execve -fno-stack-protector -z execstack -no-pie
	rm polymorphe_execve.o
