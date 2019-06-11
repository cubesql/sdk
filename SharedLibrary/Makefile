SDKDIR = ../C_SDK
CRYPTDIR = ../C_SDK/crypt
SRCDIR = ..
INCLUDE = -I$(SRCDIR) -I$(SDKDIR)/ -I$(CRYPTDIR)/ 

CC = gcc
LD = gcc
CFLAGS = $(INCLUDE) -O2
LDFLAGS = -shared -lz
RM = /bin/rm -f
UNAME := $(shell uname)

OBJS = cubesql.o pseudorandom.o aescrypt.o aeskey.o aestab.o base64.o sha1.o
PROG = libcubesql.so
ifeq ($(UNAME), Darwin)
PROG = libcubesql.dylib
endif

all:	${PROG}

${PROG}:	${OBJS}
	${LD} ${LDFLAGS} ${OBJS} -o ${PROG}

cubesql.o:	$(SDKDIR)/cubesql.c
	${CC} $(CFLAGS) -c $< -o $@

%.o:	$(CRYPTDIR)/%.c
	${CC} $(CFLAGS) -c $< -o $@

clean:	
	${RM} ${PROG} ${OBJS}
	