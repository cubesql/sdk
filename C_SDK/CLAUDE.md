# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CubeSQL C SDK — the official client library for connecting to CubeSQL database servers. Version 6.5.0, MIT licensed, authored by Marco Bambini / SQLabs. The server repo is at `/Users/marco/GitHub/cubesql`.

## Source Layout

| File | Role |
|------|------|
| `cubesql.h` | Public API — the only header consumers include |
| `csql.h` | Private internals: protocol structs, socket helpers, crypto wrappers |
| `cubesql.c` | Full implementation (~2600 lines) |
| `crypt/` | Embedded crypto: AES (Gladman), SHA-1, base64, PRNG |
| `zlib/` | Embedded zlib 1.2.5 for packet compression |
| `tests/test_bugs.c` | Unit tests (11 tests, no server required) |
| `tests/test_integration.c` | Integration tests (22 tests, requires running server) |

## Build Commands

### Unit tests (no server needed)
```bash
cd tests && make clean && make && ./test_bugs
```

### Integration tests (requires running server)
```bash
cd tests && make -f Makefile.integration clean && make -f Makefile.integration && ./test_integration
```

### Shared library
```bash
cd SharedLibrary && make        # produces libcubesql.dylib (macOS) or libcubesql.so (Linux)
```

All builds use `gcc`/`cc` and link against system zlib (`-lz`). No CMake, autotools, or package manager — just plain Makefiles. Tests compile with `-fsanitize=address -fno-omit-frame-pointer` for memory bug detection and `-DCUBESQL_DISABLE_SSL_ENCRYPTION` to exclude TLS code.

## Compile-Time Flags

- `CUBESQL_DISABLE_SSL_ENCRYPTION` — strips all TLS/LibreSSL code. AES encryption still works. Use when building without LibreSSL.
- `CUBESQL_EXPORTSDLL` — Windows DLL export (`__declspec(dllexport)`)

## Starting the CubeSQL Server for Integration Tests

Build the server from Xcode:
```bash
xcodebuild -project /Users/marco/GitHub/cubesql/XCode/cubesql.xcodeproj -scheme cubesql -configuration Debug build
```

The binary goes to `~/Library/Developer/Xcode/DerivedData/cubesql-*/Build/Products/Debug/cubesql`.

Start for testing:
```bash
mkdir -p /tmp/cubesql_test_server/databases
/path/to/cubesql -x /tmp/cubesql_test_server -d /tmp/cubesql_test_server/databases \
    -s /tmp/cubesql_test_server/cubesql.settings -f CONSOLE -p 4430 &
```

The `-s` flag is required to avoid writing to `/Library/Preferences/cubesql.settings` (which needs root). The integration tests auto-register the server on first run using `SET REGISTRATION TO`.

Default credentials: `admin` / `admin`, port `4430`.

## Architecture

### Key Opaque Types

- **`csqldb`** — database connection (socket, encryption state, error info, TLS context)
- **`csqlc`** — result cursor (column/row data, multi-buffer support for large result sets)
- **`csqlvm`** — prepared statement handle (holds server-side VM index)

### Wire Protocol

Client-server communication uses a custom binary protocol with fixed-size headers (`inhead` for requests, `outhead` for replies). The signature is `'SQLS'`. Protocol supports:

- **Compression:** zlib (transparent, negotiated per-packet via header flags)
- **Encryption:** AES-CBC (128/192/256) and/or TLS via LibreSSL
- **Authentication:** Two-phase challenge-response using SHA-1 hashes and random nonces; optional token auth

Commands are single-byte opcodes: `kCOMMAND_CONNECT` (1), `kCOMMAND_SELECT` (2), `kCOMMAND_EXECUTE` (3), `kCOMMAND_PING` (8), `kVM_PREPARE` (50), etc. — defined in `csql.h`.

### Connection Flow

1. `csql_socketconnect()` — TCP connect with IPv4/IPv6 dual-stack (tries up to 6 socket descriptors)
2. Clear-text or encrypted handshake (challenge-response with SHA-1 + AES session keys)
3. Optional TLS upgrade via LibreSSL
4. All subsequent traffic encrypted/compressed per negotiated settings

### Cursor Multi-Buffer Design

Large result sets are received in multiple network packets. Each packet's rows go into a separate buffer (`csqlc.buffer[]`). Field access computes the correct buffer and offset via `csqlc.rowsum[]` and `csqlc.rowcount[]`. Server-side cursors fetch rows on demand instead.

Custom cursors (created via `cubesql_cursor_create` with `cursor_id == -1`) use a single-buffer design with `cubesql_cursor_addrow`. These grow via realloc when `nrows >= nalloc`.

## Server Behavioral Notes

These are critical for writing correct code and tests:

### Autotransaction Mode
The server runs in autotransaction mode by default. **Each write operation (INSERT, UPDATE, DELETE, CREATE TABLE) starts an implicit transaction and holds a database-level write lock.** The lock is NOT released until you explicitly call `cubesql_commit()`. Other connections will block and eventually timeout with "Database is currently locked for write operations" if you don't commit.

For tests with multiple connections writing to the same database:
```c
cubesql_execute(db1, "INSERT INTO t VALUES (1);");
cubesql_commit(db1);   // MUST commit to release write lock
cubesql_execute(db2, "INSERT INTO t VALUES (2);");  // now conn2 can write
cubesql_commit(db2);
```

### Database Management (Custom Commands)
CubeSQL has custom SQL commands that are NOT standard SQLite:
```sql
CREATE DATABASE mydb.db IF NOT EXISTS;    -- creates a .db file in the databases directory
SET REGISTRATION TO 'Name' WITH KEY 'SERIAL';  -- registers the server
```
An unregistered server enters "restricted mode" — only admin custom commands work, all SQL is rejected.

### Column Types
The server reports column types based on SQLite's runtime storage class of actual values, not the declared column type. A column declared as `REAL` may report as `CUBESQL_Type_Text` (type 3) depending on how SQLite stores the value.

### Implicit Transactions from DDL
`CREATE TABLE`, `DROP TABLE`, and other DDL statements may leave the connection in a transaction state. Before calling `cubesql_begintransaction()`, ensure autocommit is active:
```c
cubesql_execute(db, "COMMIT;");
cubesql_clear_errors(db);
cubesql_begintransaction(db);  // now safe
```

### Error Recovery
After an error (invalid SQL, missing table, etc.), the connection remains usable. Call `cubesql_clear_errors(db)` to reset `errcode`/`errmsg`, then continue with new queries.

## API Patterns

### Basic usage
```c
csqldb *db = NULL;
cubesql_connect(&db, "localhost", 4430, "admin", "admin", 12, CUBESQL_ENCRYPTION_NONE);
cubesql_execute(db, "CREATE DATABASE test.db IF NOT EXISTS;");
cubesql_set_database(db, "test.db");
cubesql_execute(db, "CREATE TABLE t (id INTEGER, name TEXT);");
cubesql_execute(db, "INSERT INTO t VALUES (1, 'hello');");
cubesql_commit(db);  // release write lock

csqlc *c = cubesql_select(db, "SELECT * FROM t;", kFALSE);
int nrows = cubesql_cursor_numrows(c);
char *val = cubesql_cursor_cstring(c, 1, 2);  // row 1, column 2 (1-based)
cubesql_cursor_free(c);
cubesql_disconnect(db, kTRUE);
```

### Prepared statements (VM interface)
```c
csqlvm *vm = cubesql_vmprepare(db, "INSERT INTO t VALUES (?1, ?2);");
cubesql_vmbind_int(vm, 1, 42);
cubesql_vmbind_text(vm, 2, "hello", 5);
cubesql_vmexecute(vm);
cubesql_vmclose(vm);
```

### Cursor field access
- Row/column indices are **1-based**
- `cubesql_cursor_field(c, row, col, &len)` — raw bytes with length
- `cubesql_cursor_cstring(c, row, col)` — null-terminated string
- `cubesql_cursor_int(c, row, col, default_val)` — integer with default
- `cubesql_cursor_int64(c, row, col, default_val)` — 64-bit integer
- `cubesql_cursor_double(c, row, col, default_val)` — double with default
- `cubesql_cursor_field(c, CUBESQL_COLNAME, col, &len)` — column name

### Cursor seek
```c
cubesql_cursor_seek(c, CUBESQL_SEEKFIRST);  // go to row 1
cubesql_cursor_seek(c, CUBESQL_SEEKNEXT);   // go to next row
cubesql_cursor_seek(c, CUBESQL_SEEKPREV);   // go to previous row
cubesql_cursor_seek(c, CUBESQL_SEEKLAST);   // go to last row
cubesql_cursor_currentrow(c);               // get current row number (1-based)
cubesql_cursor_iseof(c);                    // true if past last row
```

## Conventions

- C89/C99 compatible — no C++ features in implementation
- Manual memory management (malloc/free); no custom allocators
- Errors are stored in the `csqldb` struct (`errcode` + `errmsg[512]`); check via `cubesql_errcode()` / `cubesql_errmsg()`
- Connection objects are **not thread-safe** — use one `csqldb*` per thread
- Network byte order: headers use `htonl`/`ntohl` for portability
- Platform ifdefs: `WIN32` for Windows (Winsock2), POSIX otherwise

## Known Issues to Skip in Audits

- Two `memcpy` issues in `generate_session_key` (comments say `// should be session_key+20`) — intentionally left as-is per author's decision.

## Test Conventions

### Unit tests (`test_bugs.c`)
- Use `assert()` for verification — tests abort on first failure
- Each test allocates its own `csqldb` via `calloc(1, sizeof(csqldb))` and frees it
- Custom cursors created via `cubesql_cursor_create` / `cubesql_cursor_addrow`
- No network I/O — purely tests internal SDK logic
- Framework macro: `RUN_TEST(fn)` calls `fn()`, prints PASS/FAIL

### Integration tests (`test_integration.c`)
- Each test function returns `int` (1=pass, 0=fail) and prints its own error details
- Each test creates its own connection via `test_connect_with_db()` helper
- Tests clean up after themselves (`DROP TABLE IF EXISTS`)
- `setup_server()` in `main()` registers the server if needed
- Uses `CUBESQL_ENCRYPTION_NONE` for most tests, `CUBESQL_ENCRYPTION_AES256` for one
- When testing concurrent writes, must commit between writes to release locks
