all: listfile.list

listfile.list: shellcode.asm
	nasm -f elf32 -l listfile.list shellcode.asm

clean:
	rm -f listfile.list *.o