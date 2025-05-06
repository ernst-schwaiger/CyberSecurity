#!/usr/bin/env python3

from pwn import *

import sys

elf = ELF("./potato")

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
break main
break login2.c:14
break login2.c:32
continue
''')

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
# Login as peter with the correct password, already causes a mem leak
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username

p.interactive()
