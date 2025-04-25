
# needs to have openssl checked out as sibling folder of potato
# git clone https://github.com/openssl/openssl.git
# and requires linking of custom built glibc 2.41

WARN_OPTS=-Wno-deprecated-declarations -Wno-unused-result
SEC_OPTS=-fno-stack-protector -z execstack -no-pie
DEBUG_OPTS=-ggdb3 -O0
INCLUDES=-Iopenssl/include -Iglibc/include -Ipotato2/src
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
	gcc $(CCOPTS) -m32 -static -o potato -Lopenssl -Lglibc/lib $(CFILES) -lssl -lcrypto -lc

clean:
	rm -f potato
