SDK := ../C_SDK
INCLUDES := -Iinclude -I$(SDK) -I$(SDK)/crypt -I$(SDK)/zlib
DEFINES := -DWIN32 -DCUBESQL_STATIC -DCUBESQL_DISABLE_SSL_ENCRYPTION
CFLAGS := -std=c99 -O2 -Wall -Wextra -Wno-misleading-indentation -Wno-multichar -Wno-attributes
LIBS := -lws2_32 -lshlwapi -lodbccp32 -luser32 -ladvapi32 -lcrypt32 -lbcrypt
LDFLAGS := -shared -Wl,--kill-at
SOURCES := src/driver.c src/setup.c $(SDK)/cubesql.c \
	$(SDK)/crypt/pseudorandom.c $(SDK)/crypt/aescrypt.c $(SDK)/crypt/aeskey.c \
	$(SDK)/crypt/aestab.c $(SDK)/crypt/base64.c $(SDK)/crypt/sha1.c $(SDK)/zlib/zlib.c

.PHONY: all win32 win64 clean test-native

all: win32 win64

win64: build/win64/cubesqlodbc.dll
win32: build/win32/cubesqlodbc.dll

build/win64/cubesqlodbc.dll: $(SOURCES) include/cubesql_odbc.h
	@mkdir -p $(@D)
	x86_64-w64-mingw32-gcc $(CFLAGS) $(DEFINES) $(INCLUDES) $(LDFLAGS) $(SOURCES) $(LIBS) -o $@

build/win32/cubesqlodbc.dll: $(SOURCES) include/cubesql_odbc.h
	@mkdir -p $(@D)
	i686-w64-mingw32-gcc $(CFLAGS) $(DEFINES) $(INCLUDES) $(LDFLAGS) $(SOURCES) $(LIBS) -o $@

test-native:
	$(MAKE) -C tests clean all

clean:
	/bin/rm -rf build
	$(MAKE) -C tests clean
