
# needs to have openssl checked out as sibling folder of potato
# git clone https://github.com/openssl/openssl.git
# and requires installation of gcc multilib
# sudo apt install gcc-multilib for m32

WARN_OPTS=-Wno-deprecated-declarations -Wno-unused-result
SEC_OPTS=-fno-stack-protector -z execstack -no-pie
DEBUG_OPTS=-ggdb3 -O0
# turn on optimizations to get some ROP gadgets
DEBUG_OPTS_ROP=-ggdb3 -O2
INCLUDES=-I../openssl/include -I/usr/include -I/usr/include/x86_64-linux-gnu -Isrc
DEFINES=-D_FORTIFY_SOURCE=0

CCOPTS = $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS) $(INCLUDES) $(DEFINES)
# include glibc statically to get additional gadgets
CCOPTS4ROP = -static $(WARN_OPTS) $(SEC_OPTS) $(DEBUG_OPTS_ROP) $(INCLUDES) $(DEFINES)

CFILES = \
	src/main.c \
	src/runr.c \
	src/sock.c \
	src/userlist.c \
	src/func.c \
	src/login2.c

HFILES = \
	src/runr.h \
	src/sock.h \
	src/user.h \
	src/userlist.h 

.PHONY: clean all

all: potato potato_rop

# binary for usual attacks
potato: $(CFILES) $(HFILES)
	gcc -m32 $(CCOPTS) -o potato $(CFILES) -L../openssl  -lssl -lcrypto 

# binary for ROP attack
potato_rop: $(CFILES) $(HFILES)
	gcc -m32 $(CCOPTS4ROP) -o potato_rop $(CFILES) -L../openssl  -lssl -lcrypto 

clean:
	rm -f potato potato_rop
