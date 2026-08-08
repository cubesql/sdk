SDK := ../C_SDK
INCLUDES := -Iinclude -I$(SDK) -I$(SDK)/crypt -I$(SDK)/zlib
DEFINES := -DWIN32 -DCUBESQL_STATIC -DCUBESQL_DISABLE_SSL_ENCRYPTION
CFLAGS := -std=c99 -O2 -Wall -Wextra -Wno-misleading-indentation -Wno-multichar -Wno-attributes
LIBS := -lws2_32 -lshlwapi -lodbccp32 -lcomctl32 -luser32 -ladvapi32 -lcrypt32 -lbcrypt
LDFLAGS := -shared -Wl,--kill-at
EXPORTS := windows/cubesqlodbc.def
RESOURCE := windows/cubesqlodbc.rc
SOURCES := src/driver.c src/setup.c $(SDK)/cubesql.c \
	$(SDK)/crypt/pseudorandom.c $(SDK)/crypt/aescrypt.c $(SDK)/crypt/aeskey.c \
	$(SDK)/crypt/aestab.c $(SDK)/crypt/base64.c $(SDK)/crypt/sha1.c $(SDK)/zlib/zlib.c

.PHONY: all win32 win64 clean test-native

all: win32 win64

win64: build/win64/cubesqlodbc.dll
win32: build/win32/cubesqlodbc.dll

build/win64/cubesqlodbc.dll: $(SOURCES) include/cubesql_odbc.h $(EXPORTS) $(RESOURCE)
	@mkdir -p $(@D)
	x86_64-w64-mingw32-windres -Iinclude $(RESOURCE) -O coff -o build/win64/resource.o
	x86_64-w64-mingw32-gcc $(CFLAGS) $(DEFINES) $(INCLUDES) $(LDFLAGS) $(SOURCES) \
		build/win64/resource.o $(EXPORTS) $(LIBS) -o $@

build/win32/cubesqlodbc.dll: $(SOURCES) include/cubesql_odbc.h $(EXPORTS) $(RESOURCE)
	@mkdir -p $(@D)
	i686-w64-mingw32-windres -Iinclude $(RESOURCE) -O coff -o build/win32/resource.o
	i686-w64-mingw32-gcc $(CFLAGS) $(DEFINES) $(INCLUDES) $(LDFLAGS) $(SOURCES) \
		build/win32/resource.o $(EXPORTS) $(LIBS) -o $@

test-native:
	$(MAKE) -C tests clean all

clean:
	/bin/rm -rf build
	$(MAKE) -C tests clean
