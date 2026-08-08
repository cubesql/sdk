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
#define CSODBC_VERSION_MINOR 1
#define CSODBC_VERSION_PATCH 0
#define CSODBC_VERSION_BUILD 0

/* Dotted form used by VERSIONINFO and by the installers. */
#define CSODBC_VERSION_STRING "1.1.0.0"

/* ODBC reports SQL_DRIVER_VER as "##.##.####". */
#define CSODBC_VERSION "01.01.0000"

#define CSODBC_COMPANY "SQLabs"
#define CSODBC_PRODUCT "CubeSQL ODBC Driver"
#define CSODBC_COPYRIGHT "Copyright (C) SQLabs"

#if defined(_WIN64) || defined(__x86_64__) || defined(__aarch64__)
#define CSODBC_ARCH_STRING "64-bit"
#else
#define CSODBC_ARCH_STRING "32-bit"
#endif

#endif
