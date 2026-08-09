# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the
ODBC driver in this repository. It is for people building and releasing the
driver. `README.md` is shipped to users — it goes into the MSI and the ZIP and
ends up in `Program Files` on a customer's machine, so keep build, test and
packaging material here, not there.

## Project Overview

Windows ODBC driver for CubeSQL, version 1.2.0, built directly on `../C_SDK`.
Windows only: `CMakeLists.txt` fails the configure step on any other platform.
The driver is compiled twice, x64 and Win32, and both are shipped — the
architecture has to match the application that loads the driver, not the OS.

## Source Layout

| Path | Role |
|------|------|
| `include/cubesql_odbc.h` | Handle structs (`cs_handle`, `cs_stmt`), driver-wide constants |
| `include/cubesql_odbc_version.h` | Version and architecture label; the `.rc` reads it too |
| `include/odbc_compat*.h` | Fills in what the toolchain's ODBC headers lack |
| `src/driver.c` | The driver: all 109 exported entry points (~3700 lines) |
| `src/setup.c` | `ConfigDSN`/`ConfigDSNW` and the setup dialog |
| `windows/cubesqlodbc.def` | The export list — 109 names; the linker enforces it |
| `windows/cubesqlodbc.rc` | Version resource |
| `windows/install.ps1`, `uninstall.ps1` | Registration through the ODBC installer API |
| `installer/cubesqlodbc.wxs` | WiX source for the MSI |
| `installer/build-msi.ps1` | Builds one MSI; takes the architecture from the DLL's PE header |
| `tests/` | Ten suites, driven by CTest |
| `Makefile` | MinGW cross-build, for development on macOS and Linux |

## Build Commands

### Visual Studio (the shipping build)

From a Visual Studio Developer PowerShell in the `ODBC` directory:

```powershell
cmake -S . -B build-vs -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build-vs --config Release

cmake -S . -B build-vs32 -A Win32 -DCMAKE_BUILD_TYPE=Release
cmake --build build-vs32 --config Release
```

Needs CMake 3.20 or later. The build links the SDK's architecture-specific
`tls.lib` by default; `-DCUBESQL_ODBC_WITH_TLS=OFF` produces a deliberately
TLS-free driver. The CRT is linked statically (`MSVC_RUNTIME_LIBRARY
"MultiThreaded"`), so the shipped DLL needs no Visual C++ redistributable.

### MinGW cross-build

The `Makefile` cross-builds testable Win32 and Win64 DLLs. They support NONE and
every AES mode but omit TLS, because the checked-in LibreSSL archives use the
MSVC object ABI:

```bash
make -j2
```

Outputs are `build/win32/cubesqlodbc.dll` and `build/win64/cubesqlodbc.dll`.

## Tests

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

Every function the driver exports is called by at least one suite. `smoke` goes
through the real Driver Manager and needs the driver registered; the rest link
the driver into the test executable and call it directly, so they need nothing
installed.

All but `core` and `types` need a live CubeSQL server on `127.0.0.1:4430`. Point
them elsewhere when configuring:

```powershell
cmake -S . -B build-vs -A x64 -DBUILD_TESTING=ON `
  -DCUBESQL_TEST_HOST=10.0.0.5 -DCUBESQL_TEST_PORT=4430 `
  -DCUBESQL_TEST_USER=admin -DCUBESQL_TEST_PASSWORD=secret
```

`install_scripts` writes to `HKEY_LOCAL_MACHINE`, so it needs an elevated
prompt. Without one it exits 77 and CTest reports it **skipped** rather than
failed. It saves and restores any pre-existing registration and never passes
`-RemoveAll`, which would delete data sources belonging to other people.

The POSIX `tests/Makefile` still cross-builds `core`, `integration` and
`conformance` with AddressSanitizer for development on macOS and Linux.

## Continuous integration

**The workflow lives at the root of the repository**, in
`.github/workflows/odbc-windows.yml` — not under `ODBC/`. GitHub only reads
workflows from `.github/workflows` at the root; a copy anywhere else is silently
ignored and never runs. One was added under `ODBC/.github/workflows/` and sat
there dead until someone noticed the suite was not running.

On every push it builds x86 and x64, installs a CubeSQL server, registers the
driver, runs the smoke test through the real Driver Manager and then the rest of
the suite under CTest, and finally builds the MSI, installs it, and reads the
registry back. It also checks three things that are cheap and have each gone
wrong before:

- the architecture in the version resource matches the binary;
- the registration scripts load under Windows PowerShell 5.1;
- the installed MSI registers `Driver` and `Setup` values that are paths that
  exist, and not `short|long` pairs.

## The MSI

Requires **WiX 5** and the .NET SDK. Pin the version:

```powershell
dotnet tool install --global wix --version "5.*"
```

Do not use the unpinned `dotnet tool install --global wix`. It installs WiX 7,
which refuses to build with `error WIX7015: You must accept the Open Source
Maintenance Fee (OSMF) EULA`. From version 6 the toolset asks commercial users
for a maintenance fee; version 5 is MS-RL and produces the same MSI. If anyone
ever wants to move to 6 or later, that is a licensing decision, not a technical
one — the output format does not change.

```powershell
.\installer\build-msi.ps1 -DriverPath .\build-vs\Release\cubesqlodbc.dll -OutputDir .\dist
```

The package platform comes from the driver's PE header, so an MSI can never
carry a driver of the wrong architecture.

The package contains no custom actions and no `Binary` table: registration goes
through `InstallODBC`, a Windows Installer standard action. Nothing from the
build toolchain ends up inside it, and the customer needs neither WiX nor .NET.
Keep it that way — a custom action would change that answer.

### Keep the installed file name within 8.3

The MSI installs the driver as `csqlodbc.dll`, not `cubesqlodbc.dll`, and the
name has to stay within eight characters plus extension.

Windows Installer stores a file name that is not 8.3 as the pair `short|long` in
the `File` table's `FileName` column, and the `InstallODBC` action writes that
column into the registry without resolving it. With the longer name the `Driver`
and `Setup` values came out as

```
C:\...\CubeSQL ODBC Driver\-pmuqzlm.dll|cubesqlodbc.dll
```

which is not a path. The file itself was laid down correctly and the driver
appeared in the ODBC Data Source Administrator, so the package looked healthy
while no application could load the driver. Supplying `ShortName` explicitly
does not help — the pair is still formed. The CI check described above exists to
catch a regression here.

## Releases

Update the version in `include/cubesql_odbc_version.h` and the `project(...)`
version in `CMakeLists.txt` so they match.

Publishing is driven by the tag, not by hand:

```bash
git tag -a odbc-v1.2.0 && git push origin odbc-v1.2.0
```

That runs the whole workflow on the tagged commit and, only if it passes,
creates the GitHub release from the binaries CI just tested: the two MSIs, two
ZIP archives holding the bare DLL with the registration scripts, and
`SHA256SUMS.txt`. Nothing built on a workstation is uploaded.

Because the release is produced from the tagged commit, a fix pushed to `master`
after tagging does not reach it. Move the tag before pushing it, or tag again.

## Traps that have already cost time

**`$LASTEXITCODE` after a PowerShell script.** It is set by native executables
only. `install.ps1` runs one just when it has to change registry view: to
register a 32-bit driver from a 64-bit PowerShell it re-launches itself in
`SysWOW64`. Registering a driver of the same bitness as the process runs nothing
native, so the variable keeps whatever it held before — `$null` in a fresh
session. A test that compared it with `0` passed on x86 and failed on x64, and
passed on a workstation only because something native had run earlier in the
session. Errors from these scripts arrive as exceptions; they run with
`$ErrorActionPreference = "Stop"`.

**Type accelerators in Windows PowerShell 5.1.** `[ushort]` and `[ulong]` are
7.x only. `install.ps1` used `[ushort]` and was dead on arrival on a stock
Windows, throwing before it wrote anything. Use `[uint16]`/`[uint64]`.

**`SQLConfigDriver`'s `fRequest`.** `ODBC_INSTALL_INQUIRY` (1) reports success
without touching the registry. The scripts must pass `ODBC_INSTALL_COMPLETE`
(2).

**The driver declares ODBC 2.0, deliberately.** `DriverODBCVer=02.00` in the
`.wxs` and `CSODBC_DRIVER_ODBC_VERSION` in the header. The whole ODBC 2.0 API is
implemented — 23 Core, 15 Level 1, 16 Level 2 — so the declaration is more
modest than what is provided. Declaring 3.x is not a one-line change: with a 3.x
declaration and no descriptor handles the Windows Driver Manager faults inside
`ODBC32.dll` on the first `SQLExecDirect`. Implement the implicit descriptors
first. `SQLGetDescField` and friends are not exported and `SQLGetFunctions`
reports them absent, which is the correct answer today.

**Never leave a diagnostic enumeration without an end.** Through 1.1.0, any
statement that failed on a connection with no current database hung the calling
application and grew until it ran out of memory — `SELECT 1;` was enough. It was
tempting to blame `ODBC32.dll`, because the loop does run there and the driver
returns `SQL_ERROR` promptly. The cause was in the driver: `SQLError` asked for
diagnostic record 1 on every call and so never returned `SQL_NO_DATA`, and
because the driver declares ODBC 2.0 the Driver Manager builds its own
diagnostic queue by calling `SQLError` until it is exhausted. That harvest runs
*inside* `SQLExecDirect`, which is why the application never saw the call
return, and why it happened even when the application never asked for the error.

Measured, one binary against the other, same probe: the 1.1.0 driver never came
back and was killed at the memory cap; the current one returns `SQL_ERROR` in
6 MB. Fixed in 1.2.0 by `cs_diag_take_next`, which `SQLError` and `SQLErrorW`
share.

Two lessons worth keeping. First, a defect whose symptom is *no return* cannot
be caught by checking a return code — the guarded call in `tests/test_windows.c`
watches time and process growth and kills itself, so a regression reports as a
test failure instead of wedging the machine. Second, that check has to go
through the Driver Manager: the native suites link the driver directly and never
cross the path where the loop lives, so they cannot see it.

**Column types come from the catalogue, not the value.** CubeSQL reports the
runtime storage class, so a `REAL` column whose values are stored as text would
arrive as `SQL_VARCHAR`. When the runtime type is text the driver asks
`PRAGMA table_info` what the column was declared as, once per result set.
Expressions have no declared type and are reported as the server describes them.

## Conventions

- C99, MSVC and MinGW; `/W4` clean except for the four warnings suppressed in
  `CMakeLists.txt`
- Every exported name lives in `windows/cubesqlodbc.def`. Adding an entry point
  means adding it there too, or the linker drops it
- ANSI and Unicode entry points share one implementation: `cs_i_SQLFoo` does the
  work, `SQLFoo` and `SQLFooW` marshal. Do not let the two lists drift — an
  identifier handled in `SQLColAttribute` but not in `SQLColAttributeW` is a bug
  that only shows up in Unicode consumers
- Calls are serialised per connection with a `CRITICAL_SECTION`, as ODBC requires
- Unimplemented optional features return `HYC00` rather than behaving incorrectly
