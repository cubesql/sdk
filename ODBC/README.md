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

Because explicit descriptors are not implemented, the driver registers itself
with `DriverODBCVer=02.00`, which lets the Windows Driver Manager provide the
ODBC 3.x descriptor mappings. One consequence is that dynamic
`SQL_ATTR_CURRENT_CATALOG` changes are not exposed through the Driver Manager:
select a database with `DATABASE=` in the connection string, or run a CubeSQL
`USE DATABASE database_name;` command after connecting.

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

Requires the WiX .NET tool (`dotnet tool install --global wix`):

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

Two native suites call the driver ABI directly against a live CubeSQL server,
under AddressSanitizer. `test_odbc_integration` covers connections, DDL,
prepared parameters, BLOBs, binding, partial `SQLGetData`, scrolling, rollback,
metadata, and diagnostics. `test_odbc_conformance` covers the behaviour ODBC
consumers depend on: parameter arrays, column-wise and row-wise rowset fetch,
scrolling across rowsets, attribute tolerance, a full `SQLGetInfo` sweep,
catalog handling, escape sequence translation, non-ASCII round trips, concurrent
use of one connection from several threads, and disconnect semantics.

To start an isolated CubeSQL instance, run both suites, and stop the server:

```bash
make -C tests clean all && (cd tests && ./run_local_server.sh)
```

The script leaves its temporary server directory in place and prints the path,
so the server log and test database stay available for inspection. Point it at a
different server binary with `CUBESQL_SERVER_BIN`.

To run a suite against a server you already have:

```bash
make -C tests
CUBESQL_ODBC_HOST=127.0.0.1 CUBESQL_ODBC_PORT=4430 CUBESQL_ODBC_USER=admin CUBESQL_ODBC_PASSWORD=admin tests/test_odbc_conformance
```

For a Windows Driver Manager smoke test, install the driver, build the CMake
`cubesql_odbc_smoke` target, then set:

```powershell
$env:CUBESQL_ODBC_CONNECTION_STRING = "DRIVER={CubeSQL ODBC Driver};SERVER=localhost;PORT=4430;UID=admin;PWD=admin;DATABASE=app.db;ENCRYPTION=AES256;"
.\build-vs\Release\cubesql_odbc_smoke.exe
```

GitHub Actions runs the smoke test through the real Windows Driver Manager for
both MSVC Win32 and x64 builds. Each matrix job installs a pinned CubeSQL
Windows MSI, registers the matching driver architecture, **verifies the driver
was registered in the correct 32-bit or 64-bit registry view**, runs the smoke
target, builds and round-trips the MSI, then cleans up. Successful runs publish
`cubesql-odbc-windows-x86` and `cubesql-odbc-windows-x64` artifacts for 30 days.
See `.github/workflows/odbc-windows.yml`.

## Releases

Push an annotated `odbc-v*` tag after updating `include/cubesql_odbc_version.h`
and the CMake project version to match:

```bash
git tag -a odbc-v1.1.0 -m "CubeSQL ODBC 1.1.0"
git push origin odbc-v1.1.0
```

The tag runs both Windows jobs first. Only if Win32 and x64 both pass does the
workflow create or update the GitHub Release with the versioned MSIs, the ZIP
packages, and a release-level `SHA256SUMS.txt`.
