all:
	python3 main.py 127.0.0.1 8989

build_asm:
	nasm -f elf64 -o build/tmp.o main.asm && ld build/tmp.o -o build/reverse_shell

show_opcode:
	for i in $(objdump -D build/reverse_shell |grep "^ " |cut -f2); do echo -n '\x'$i; done; echo

build_test:
	gcc test_shellcode.c -o build/test_shellcode -fno-stack-protector -z execstack -no-pie

clean:
	rm build/*
