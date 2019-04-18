SDKDIR = ../../../C_SDK
CRYPTDIR = ../../../C_SDK/crypt
SRCDIR = ..
INCLUDE = -I$(SRCDIR) -I$(SDKDIR)/ -I$(CRYPTDIR)/ 

CC = gcc
LD = gcc
CFLAGS = $(INCLUDE) -O2
LDFLAGS = -lz
RM = /bin/rm -f

OBJS = testapp.o cubesql.o pseudorandom.o aescrypt.o aeskey.o aestab.o base64.o sha1.o

PROG = testapp
all:	${PROG}

${PROG}:	${OBJS}
	${LD} ${LDFLAGS} ${OBJS} -o ${PROG}

testapp.o:	$(SRCDIR)/testapp.c
	${CC} $(CFLAGS) -c $< -o $@

cubesql.o:	$(SDKDIR)/cubesql.c
	${CC} $(CFLAGS) -c $< -o $@

%.o:	$(CRYPTDIR)/%.c
	${CC} $(CFLAGS) -c $< -o $@

clean:	
	${RM} ${PROG} ${OBJS}

