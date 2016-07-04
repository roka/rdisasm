all: disasm.o rdisasm

elf.o:
	gcc -c bin/elf.c

disasm.o:
	gcc -c disasm.c

x86-64.o:
	gcc -c arch/x86-64.c

cpu.o:
	gcc -c tc/cpu.c

rdisasm: disasm.o elf.o x86-64.o
	gcc disasm.o elf.o x86-64.o -o rdisasm

clean:
	rm -f *.o a.out rdisasm
