SDKDIR = ..
CRYPTDIR = ../crypt
INCLUDE = -I$(SDKDIR)/ -I$(CRYPTDIR)/

CC = cc
CFLAGS = $(INCLUDE) -O0 -g -DCUBESQL_DISABLE_SSL_ENCRYPTION -fsanitize=address -fno-omit-frame-pointer
LDFLAGS = -lz -fsanitize=address
RM = /bin/rm -f

OBJS = test_bugs.o cubesql.o pseudorandom.o aescrypt.o aeskey.o aestab.o base64.o sha1.o
PROG = test_bugs

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(PROG)

test_bugs.o: test_bugs.c
	$(CC) $(CFLAGS) -c $< -o $@

cubesql.o: $(SDKDIR)/cubesql.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: $(CRYPTDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(PROG) $(OBJS)

test: $(PROG)
	./$(PROG)

.PHONY: all clean test
