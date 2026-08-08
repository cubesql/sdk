SDK := ../../C_SDK
INCLUDES := -I../include -I$(SDK) -I$(SDK)/crypt
CFLAGS := -std=c99 -O0 -g -Wall -Wextra -Wno-misleading-indentation \
	-DCUBESQL_DISABLE_SSL_ENCRYPTION -fsanitize=address -fno-omit-frame-pointer
SOURCES := test_integration.c ../src/driver.c $(SDK)/cubesql.c \
	$(SDK)/crypt/pseudorandom.c $(SDK)/crypt/aescrypt.c $(SDK)/crypt/aeskey.c \
	$(SDK)/crypt/aestab.c $(SDK)/crypt/base64.c $(SDK)/crypt/sha1.c

.PHONY: all clean run
all: test_odbc_core test_odbc_integration test_odbc_conformance

test_odbc_conformance: test_conformance.c ../src/driver.c $(filter-out test_integration.c ../src/driver.c,$(SOURCES))
	$(CC) $(CFLAGS) $(INCLUDES) test_conformance.c ../src/driver.c \
		$(filter-out test_integration.c ../src/driver.c,$(SOURCES)) -lz -lpthread -o $@

test_odbc_core: test_core.c ../src/driver.c $(filter-out test_integration.c ../src/driver.c,$(SOURCES))
	$(CC) $(CFLAGS) $(INCLUDES) test_core.c ../src/driver.c \
		$(filter-out test_integration.c ../src/driver.c,$(SOURCES)) -lz -o $@

test_odbc_integration: $(SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) $(SOURCES) -lz -o $@

run: test_odbc_integration
	./test_odbc_integration

clean:
	/bin/rm -f test_odbc_core test_odbc_integration test_odbc_conformance
