# CubeSQL ODBC Driver

Windows ODBC 3.8 driver for CubeSQL, built directly on the official C SDK. Both
32-bit and 64-bit drivers are supported.

## Features

- ANSI and UTF-16 ODBC entry points
- DSN and DSN-less connections, IPv4/IPv6 through the C SDK
- CubeSQL NONE, AES-128/192/256, TLS, and TLS+AES encryption modes
- Direct and prepared execution, typed input parameters, and streamed
  data-at-execution (`SQLParamData`/`SQLPutData`)
- Typed column binding, chunked `SQLGetData`, static scrolling, and BLOBs
- ODBC autocommit plus explicit commit/rollback
- Diagnostics with SQLSTATE mapping and recovery after statement errors
- `SQLTables`, `SQLColumns`, `SQLPrimaryKeys`, `SQLForeignKeys`,
  `SQLStatistics`, `SQLSpecialColumns`, and `SQLGetTypeInfo`
- Programmatic user/system DSN configuration and PowerShell installation

Explicit descriptors, asynchronous execution, updatable cursors, output
parameters, row-wise binding, and parameter/row arrays larger than one are not
advertised. They return `HYC00` instead of silently behaving incorrectly.

## Build with Visual Studio (release build, TLS enabled)

Use a Visual Studio Developer PowerShell from the `ODBC` directory:

```powershell
cmake -S . -B build-vs -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build-vs --config Release

cmake -S . -B build-vs32 -A Win32 -DCMAKE_BUILD_TYPE=Release
cmake --build build-vs32 --config Release
```

The CMake build links the SDK's architecture-specific `tls.lib` by default.
Use `-DCUBESQL_ODBC_WITH_TLS=OFF` only for a deliberately TLS-free build.

The repository `Makefile` cross-builds testable Win32 and Win64 DLLs with
MinGW. Those artifacts support NONE and every AES mode, but omit TLS because
the checked-in LibreSSL archives use the MSVC object ABI:

```bash
make -j2
```

Outputs are `build/win32/cubesqlodbc.dll` and
`build/win64/cubesqlodbc.dll`.

## Install

Run an elevated PowerShell. The architecture of the driver must match the
application using it:

```powershell
.\windows\install.ps1 -DriverPath .\build-vs\Release\cubesqlodbc.dll
```

Optionally create a system DSN at the same time:

```powershell
.\windows\install.ps1 `
  -DriverPath .\build-vs\Release\cubesqlodbc.dll `
  -Dsn CubeSQLLocal -Server localhost -Port 4430 `
  -User admin -Database app.db -Encryption AES256
```

Passwords are intentionally never stored in a DSN. Supply `PWD` when opening
the connection.

## Connection string

```text
DRIVER={CubeSQL ODBC Driver};SERVER=localhost;PORT=4430;UID=admin;PWD=admin;DATABASE=app.db;ENCRYPTION=AES256;TIMEOUT=12;
```

Aliases `HOST`, `USER`, `USERNAME`, `PASSWORD`, `DB`, and `ENC` are accepted.
Values containing semicolons or closing braces use standard ODBC braces; a
literal `}` is doubled.

## Tests

The native integration harness calls the driver ABI directly while using the
real C SDK and a live CubeSQL server:

```bash
make -C tests
CUBESQL_ODBC_HOST=127.0.0.1 \
CUBESQL_ODBC_PORT=4430 \
CUBESQL_ODBC_USER=admin \
CUBESQL_ODBC_PASSWORD=admin \
tests/test_odbc_integration
```

To start an isolated CubeSQL instance on port 4540, register only that test
instance, run the complete integration suite, and stop the server afterward:

```bash
cd /Users/marco/SQLabs/sdk/ODBC/tests
make clean all
./run_local_server.sh
```

The script leaves its temporary server directory in place and prints its path,
so the server log and test database remain available for inspection.

It covers connection strings, database creation/selection, DDL, prepared
parameters, BLOBs, binding, partial `SQLGetData`, scrolling, rollback,
metadata, diagnostics/recovery, and streamed parameters under AddressSanitizer.

For a Windows Driver Manager smoke test, install the driver, build the CMake
`cubesql_odbc_smoke` target, then set:

```powershell
$env:CUBESQL_ODBC_CONNECTION_STRING = "DRIVER={CubeSQL ODBC Driver};SERVER=localhost;PORT=4430;UID=admin;PWD=admin;DATABASE=app.db;ENCRYPTION=AES256;"
.\build-vs\Release\cubesql_odbc_smoke.exe
```

GitHub Actions runs this smoke test through the real Windows Driver Manager for
both MSVC Win32 and x64 builds. Each matrix job verifies and silently installs
the matching pinned CubeSQL 5.9.0 Windows MSI, waits for its service on port
4430, registers the matching driver architecture, runs the CTest smoke target,
packages the tested DLL with its install scripts, checksum, license, and
documentation, then uninstalls the server and unregisters the driver.
Successful runs publish separate `cubesql-odbc-windows-x86` and
`cubesql-odbc-windows-x64` downloadable artifacts for 30 days. See
`.github/workflows/odbc-windows.yml`.

## Permanent releases

Push an annotated `odbc-v*` tag only after updating the driver and CMake
versions to match. For example:

```bash
git tag -a odbc-v1.0.0 -m "CubeSQL ODBC 1.0.0"
git push origin odbc-v1.0.0
```

The tag runs both Windows smoke-test jobs first. Only if Win32 and x64 pass,
the workflow creates or updates the corresponding GitHub Release with
versioned x86/x64 ZIP files and a release-level `SHA256SUMS.txt`. GitHub
Release assets remain available until the release or asset is explicitly
deleted; the 30-day Actions artifact setting does not apply to them.
