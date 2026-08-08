# CubeSQL ODBC Driver

Windows ODBC driver for CubeSQL, built directly on the official C SDK. Separate
32-bit and 64-bit builds are provided; the architecture of the driver must match
the application that loads it, not the operating system.

## Install

Download the MSI for the architecture your application uses and run it. Most
users need **x64**; 32-bit Office, 32-bit Access, and older line-of-business
applications need **x86**. Installing both side by side is supported and common.

| Application | Package |
|---|---|
| 64-bit Excel, Power BI Desktop, 64-bit ODBC Data Source Administrator | `cubesql-odbc-x64-*.msi` |
| 32-bit Excel or Access, 32-bit applications, `C:\Windows\SysWOW64\odbcad32.exe` | `cubesql-odbc-x86-*.msi` |

After installation the driver appears as **CubeSQL ODBC Driver** in the ODBC
Data Source Administrator, with its version and publisher shown on the
**Drivers** tab. The 32-bit and 64-bit builds report their architecture in the
file description, so the two are easy to tell apart.

The MSI installs the driver as `csqlodbc.dll` under
`%ProgramFiles%\SQLabs\CubeSQL ODBC Driver`. The name is deliberately within
8.3: Windows Installer stores a longer name as a `short|long` pair and the
`InstallODBC` action writes that pair into the registry unresolved, which
leaves the `Driver` value pointing at something that is not a path. The ZIP and
the build output keep the full `cubesqlodbc.dll` name.

### Creating a data source

Open the ODBC Data Source Administrator matching the driver's architecture,
choose **Add**, select **CubeSQL ODBC Driver**, and fill in the dialog. It asks
for the host, port, encryption mode, timeout, user name, password, and database,
with a **Test** button that opens a real connection and a **Refresh** button
that lists the databases on the server.

Passwords are never written into a data source. Applications supply `PWD` in the
connection string, or the driver asks for it when the application requests a
prompt.

### Scripted installation

For unattended deployment, use the PowerShell scripts shipped alongside the MSI.
Run them from an **elevated** PowerShell:

```powershell
.\install.ps1 -DriverPath .\cubesqlodbc.dll
```

Optionally create a system data source at the same time:

```powershell
.\install.ps1 -DriverPath .\cubesqlodbc.dll -Dsn CubeSQLLocal -Server localhost -Port 4430 -User admin -Database app.db -Encryption AES256
```

The script reads the driver's architecture from the PE header of the DLL and
re-launches itself in a PowerShell of the matching bitness, so a 32-bit driver
always lands in the 32-bit ODBC registry view regardless of where the file sits
on disk. Registration goes through the ODBC installer API, so the driver's usage
count is maintained and removing one product cannot unregister a driver another
product still needs.

To remove it:

```powershell
.\uninstall.ps1 -Architecture 64
```

If PowerShell refuses to run the script ("running scripts is disabled on this
system"), start it as:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -DriverPath .\cubesqlodbc.dll
```

## Connection string

```text
DRIVER={CubeSQL ODBC Driver};SERVER=localhost;PORT=4430;UID=admin;PWD=admin;DATABASE=app.db;ENCRYPTION=AES256;TIMEOUT=12;
```

`DATABASE=` is not optional in practice — see *Always select a database* below.

| Keyword | Aliases | Default | Meaning |
|---|---|---|---|
| `SERVER` | `HOST` | `localhost` | Server host name or IP address (IPv4 or IPv6) |
| `PORT` | | `4430` | Server port |
| `UID` | `USER`, `USERNAME` | | User name (required) |
| `PWD` | `PASSWORD` | | Password |
| `DATABASE` | `DB` | | Database to select after connecting |
| `ENCRYPTION` | `ENC` | `AES256` | `NONE`, `AES128`, `AES192`, `AES256`, `SSL`, `SSL+AES128`, `SSL+AES192`, `SSL+AES256` |
| `TIMEOUT` | `LOGINTIMEOUT` | `12` | Connection timeout in seconds |
| `CHARSET` | | `ANSI` | `ANSI` or `UTF8`; see *Character sets* |
| `DSN` | | | Use a configured data source; other keywords override its values |

Values containing semicolons or closing braces use standard ODBC braces; a
literal `}` is doubled.

The completed connection string the driver hands back from `SQLDriverConnect`
never contains the password, because applications routinely persist it.

## Connections and connection-limited licences

CubeSQL counts **open TCP sockets**, not active queries, and the count is
incremented when a socket is accepted, before authentication. A licence for *n*
connections therefore allows *n* sockets to exist at once; a socket that is open
but idle still occupies one until it is closed or reaped.

This interacts badly with **ODBC connection pooling**. When pooling is enabled —
ADO and OLE DB for ODBC, `System.Data.Odbc`, and the per-driver setting in the
ODBC Data Source Administrator all enable it — `SQLDisconnect` does *not* close
the socket. It returns the connection to the pool, where it stays open for
`CPTimeout` seconds (60 by default). If the application connects again before
that expires, the Driver Manager opens a **second** socket, and a
single-connection licence rejects it.

The symptom is a connection that works sometimes and fails other times with
*"The maximum number of allowed connections has been reached."* The driver
reports that condition as SQLSTATE `08004` with an explanation.

To fix it:

1. **Disable pooling for this driver.** In the ODBC Data Source Administrator,
   open the **Connection Pooling** tab, double-click **CubeSQL ODBC Driver**, and
   select *Don't pool connections to this driver*. Applications can instead set
   `SQL_ATTR_CONNECTION_POOLING` to `SQL_CP_OFF` on the environment handle.
2. **Check what is actually connected.** `SHOW CONNECTIONS;` on the server, or
   the admin console, lists the live sockets and who owns them.
3. **Size the licence for ODBC.** Many ODBC consumers — Excel and Power Query,
   Access, SSIS, most reporting tools — open several connections in parallel by
   design. A single-connection licence cannot serve them reliably no matter how
   pooling is configured; three to five is a realistic minimum.

An abandoned socket (a client that crashed without closing cleanly) is reclaimed
by the server's ping timeout, 300 seconds by default.

## Character sets

CubeSQL stores text as UTF-8. ODBC defines `SQL_C_CHAR` as the application's
character set, so on Windows the driver converts between UTF-8 and the process
ANSI code page on the `SQL_C_CHAR` paths, in both directions. Applications that
prefer to handle UTF-8 themselves can switch the conversion off with
`CHARSET=UTF8` in the connection string.

The `SQL_C_WCHAR` paths always carry the full Unicode value and are unaffected.
Applications that handle non-ASCII data should prefer them.

## Features

- ANSI and UTF-16 ODBC entry points
- DSN and DSN-less connections, IPv4/IPv6 through the C SDK
- CubeSQL NONE, AES-128/192/256, TLS, and TLS+AES encryption modes
- A guided setup dialog with connection testing and database discovery, plus a
  login prompt for `SQLDriverConnect`
- Direct and prepared execution, typed input parameters, parameter arrays, and
  streamed data-at-execution (`SQLParamData`/`SQLPutData`)
- Block (rowset) fetch with column-wise and row-wise binding, bind offsets, row
  status arrays, static scrolling, chunked `SQLGetData`, and BLOBs
- ODBC escape sequence translation: `{d}`, `{t}`, `{ts}`, `{escape}`, `{oj}`,
  and the `{fn ...}` scalar functions reported by `SQLGetInfo`
- ODBC autocommit plus explicit commit/rollback; an open transaction is rolled
  back on disconnect
- Complete `SQLGetInfo`, diagnostics with SQLSTATE mapping, and recovery after
  statement errors
- `SQLTables`, `SQLColumns`, `SQLPrimaryKeys`, `SQLForeignKeys`,
  `SQLStatistics`, `SQLSpecialColumns`, and `SQLGetTypeInfo`, including the
  catalog, schema, and table-type enumeration special cases
- Thread-safe: calls are serialised per connection, as ODBC requires

Explicit descriptors, asynchronous execution, updatable cursors, output
parameters, and bookmarks are not implemented. They return `HYC00` rather than
silently behaving incorrectly.

## ODBC conformance

The driver registers as **ODBC 2.0** (`DriverODBCVer=02.00`) and reports
`SQL_OAC_LEVEL1` for `SQL_ODBC_API_CONFORMANCE`. In practice it implements the
whole ODBC 2.0 API — all 23 Core functions, all 15 Level 1, and all 16 Level 2 —
so the declared level is deliberately more modest than what is provided.

What this means for an application:

- Everything an ODBC 2.x consumer asks for works, in both the ANSI and the
  Unicode entry points, and in both the 2.x and the 3.x spellings of the same
  request (`SQL_COLUMN_NAME` as well as `SQL_DESC_NAME`, `SQL_ROWSET_SIZE` as
  well as `SQL_ATTR_ROW_ARRAY_SIZE`, `SQL_C_TIMESTAMP` as well as
  `SQL_C_TYPE_TIMESTAMP`).
- Fourteen ODBC **3.0-only** InfoTypes, and `SQL_ATTR_METADATA_ID`, are refused
  by the *Driver Manager* before they reach the driver, with `HY096` and
  `HY092`. The driver implements them; the Driver Manager does not forward
  3.0-only requests to a driver that declares 2.0. This is expected and harmless
  for 2.x consumers.
- `SQL_ATTR_CURRENT_CATALOG` cannot be used to switch database after connecting.
  Select the database with `DATABASE=` in the connection string, or run
  `USE DATABASE database_name;`.

Moving to ODBC 3.x would remove those restrictions, but it requires implementing
the implicit descriptors first: with a 3.x declaration and no descriptor handles
the Windows Driver Manager faults inside `ODBC32.dll` on the first
`SQLExecDirect`. `SQLGetDescField` and friends are not exported, and
`SQLGetFunctions` reports them absent, which is the correct answer today.

## Always select a database

Give every connection a database, either with `DATABASE=` in the connection
string, in the data source, or by running `USE DATABASE database_name;` as the
first statement.

This matters beyond convenience: on a connection with **no** current database an
ordinary statement — even `SELECT 1;` — fails on the server, and the Windows
Driver Manager does not return from the failing call. It keeps allocating until
the client process runs out of memory, which on a machine with little RAM takes
the whole system down with it. The driver itself returns `SQL_ERROR` promptly;
the loop is inside `ODBC32.dll`.

The commands that are meaningful without a current database — `SHOW DATABASES;`,
`USE DATABASE`, `CREATE DATABASE` — are unaffected.

## Data types

CubeSQL reports the *runtime* type of a column, and for a `REAL` column it
reports text. Taken literally that would make every floating-point column arrive
as `SQL_VARCHAR`, and consumers would treat numbers as strings. When the runtime
type is text the driver therefore asks the catalogue what the column was
declared as, once per result set and only when it can help:

| Declared | Reported | Typical .NET type |
|---|---|---|
| `INTEGER` | `SQL_BIGINT` | `Int64` |
| `REAL`, `FLOAT`, `DOUBLE` | `SQL_DOUBLE` | `Double` |
| `NUMERIC`, `DECIMAL` | `SQL_DECIMAL` | `Decimal` |
| `TEXT`, `CHAR`, `VARCHAR`, `CLOB` | `SQL_VARCHAR` | `String` |
| `BLOB` | `SQL_LONGVARBINARY` | `Byte[]` |
| `BOOLEAN` | `SQL_BIT` | `Boolean` |
| `DATE`, `TIME`, `TIMESTAMP`, `DATETIME` | `SQL_TYPE_*` | `DateTime` |

Columns that are expressions rather than table columns have no declared type and
are reported as the server describes them.

## Build

### Visual Studio (the shipping build)

From a Visual Studio Developer PowerShell in the `ODBC` directory:

```powershell
cmake -S . -B build-vs -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build-vs --config Release

cmake -S . -B build-vs32 -A Win32 -DCMAKE_BUILD_TYPE=Release
cmake --build build-vs32 --config Release
```

The CMake build links the SDK's architecture-specific `tls.lib` by default. Use
`-DCUBESQL_ODBC_WITH_TLS=OFF` only for a deliberately TLS-free build.

### MSI

Requires **WiX 5** and the .NET SDK. Install the version explicitly:

```powershell
dotnet tool install --global wix --version "5.*"
```

Do not use the unpinned `dotnet tool install --global wix`: it now installs WiX
7, which refuses to build with `error WIX7015: You must accept the Open Source
Maintenance Fee (OSMF) EULA`.

```powershell
.\installer\build-msi.ps1 -DriverPath .\build-vs\Release\cubesqlodbc.dll -OutputDir .\dist
```

The package platform is derived from the driver's PE header, so an MSI can never
carry a driver of the wrong architecture.

### MinGW cross-build

The repository `Makefile` cross-builds testable Win32 and Win64 DLLs with MinGW.
Those artifacts support NONE and every AES mode, but omit TLS because the
checked-in LibreSSL archives use the MSVC object ABI:

```bash
make -j2
```

Outputs are `build/win32/cubesqlodbc.dll` and `build/win64/cubesqlodbc.dll`.

## Tests

The suite is driven by CTest and runs on Windows for both architectures. It
needs a live CubeSQL server on `127.0.0.1:4430` (configurable, see below).

```powershell
cmake -S . -B build-vs -A x64 -DBUILD_TESTING=ON
cmake --build build-vs --config Release
cd build-vs
ctest -C Release --output-on-failure
```

| Suite | What it covers |
|---|---|
| `smoke` | the real Windows Driver Manager, end to end |
| `core` | handles, environment attributes, `SQLGetFunctions` |
| `integration` | connections, DDL, prepared parameters, BLOBs, binding, partial `SQLGetData`, scrolling, rollback, metadata |
| `conformance` | parameter arrays, rowset fetch column-wise and row-wise, attribute tolerance, escape translation, non-ASCII round trips, several threads on one connection, disconnect semantics |
| `types` | declared types, every C type including both date/time spellings, `NULL`, truncation with `01004`, chunked `SQLGetData` |
| `unicode` | the Unicode entry points and the ODBC 2.x spellings against their 3.x equivalents |
| `diagnostics` | `SQLError` record walking, diagnostic fields, catalog functions |
| `setup` | `ConfigDSN`/`ConfigDSNW` with no user interface, add, configure, remove, error cases |
| `aliases` | every ODBC 2.x alias, the A/W variants, and the optional functions |
| `install_scripts` | `install.ps1`/`uninstall.ps1` against the registry |

Every function the driver exports is called by at least one suite.

`install_scripts` writes to `HKEY_LOCAL_MACHINE`, so it needs an elevated
prompt. Without one it reports itself **skipped**, with an explanation, rather
than failing. It saves and restores any pre-existing registration, and does not
touch data sources belonging to anyone else.

Point the suite at a different server when configuring:

```powershell
cmake -S . -B build-vs -A x64 -DBUILD_TESTING=ON `
  -DCUBESQL_TEST_HOST=10.0.0.5 -DCUBESQL_TEST_PORT=4430 `
  -DCUBESQL_TEST_USER=admin -DCUBESQL_TEST_PASSWORD=secret
```

`.github/workflows/windows.yml` builds and runs the suite for x64 and Win32. It
also checks two things that are cheap and have gone wrong before: that the
architecture in the version resource matches the binary, and that the PowerShell
scripts load under Windows PowerShell 5.1.

The POSIX `tests/Makefile` still cross-builds `core`, `integration` and
`conformance` with AddressSanitizer for development on macOS and Linux.

## Releases

Update the version in `include/cubesql_odbc_version.h` and the CMake project
version so they match, build both architectures, then build the MSIs:

```powershell
.\installer\build-msi.ps1 -DriverPath .\build-vs\Release\cubesqlodbc.dll   -OutputDir .\dist
.\installer\build-msi.ps1 -DriverPath .\build-vs32\Release\cubesqlodbc.dll -OutputDir .\dist
```

The package platform is taken from the driver's PE header, so the x64 and x86
packages are named from the binaries they actually carry.
