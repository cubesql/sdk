/*
 * Single source of truth for the CubeSQL ODBC driver version.
 *
 * This header is included both by the C sources and by the Windows resource
 * script (windows/cubesqlodbc.rc), so it must contain nothing but preprocessor
 * definitions that the resource compiler can also parse.
 */
#ifndef CUBESQL_ODBC_VERSION_H
#define CUBESQL_ODBC_VERSION_H

#define CSODBC_VERSION_MAJOR 1
#define CSODBC_VERSION_MINOR 2
#define CSODBC_VERSION_PATCH 1
#define CSODBC_VERSION_BUILD 0

/* Dotted form used by VERSIONINFO and by the installers. */
#define CSODBC_VERSION_STRING "1.2.1.0"

/* ODBC reports SQL_DRIVER_VER as "##.##.####". */
#define CSODBC_VERSION "01.02.0001"

#define CSODBC_COMPANY "SQLabs"
#define CSODBC_PRODUCT "CubeSQL ODBC Driver"
#define CSODBC_COPYRIGHT "Copyright (C) SQLabs"

/*
 * Architecture label used by the VERSIONINFO block.
 *
 * _WIN64 / __x86_64__ / __aarch64__ are COMPILER macros: rc.exe does not define
 * any of them, so a resource script that relies on them alone always compiled
 * the 32-bit branch and every build - including x64 - described itself as
 * "(32-bit)". MinGW hid the bug because windres does define the target macros.
 *
 * The build system therefore passes CSODBC_ARCH_64 explicitly, to the resource
 * compiler as well as to the C compiler. The compiler-macro test is kept as a
 * fallback for builds that do not define it (for example the plain Makefile).
 */
#if defined(CSODBC_ARCH_64)
#  if CSODBC_ARCH_64
#    define CSODBC_ARCH_STRING "64-bit"
#  else
#    define CSODBC_ARCH_STRING "32-bit"
#  endif
#elif defined(_WIN64) || defined(__x86_64__) || defined(__aarch64__)
#  define CSODBC_ARCH_STRING "64-bit"
#else
#  define CSODBC_ARCH_STRING "32-bit"
#endif

#endif
