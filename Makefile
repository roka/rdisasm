all: disasm.o rdisasm

elf.o:
	gcc -c bin/elf.c

disasm.o:
	gcc -c disasm.c

ia64.o:
	gcc -c arch/ia64.c

cpu.o:
	gcc -c tc/cpu.c

rdisasm: disasm.o elf.o ia64.o
	gcc disasm.o elf.o ia64.o -o rdisasm

clean:
	rm -f *.o a.out rdisasm

test: rdisasm
	python3 script/test.py
