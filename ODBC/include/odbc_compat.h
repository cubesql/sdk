/*
 * Minimal ODBC 3.x ABI used only by the native integration test build.
 * Windows production builds always use Microsoft's sql.h/sqlext.h/sqlucode.h.
 *
 * Only the types live here. Every SQL_* constant comes from
 * odbc_compat_constants.h, which is generated from the real Windows ODBC
 * headers so the native tests cannot drift from the production build.
 */
#ifndef CUBESQL_ODBC_COMPAT_H
#define CUBESQL_ODBC_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#define SQL_API
typedef unsigned char SQLCHAR;
typedef uint16_t SQLWCHAR;
typedef signed char SQLSCHAR;
typedef int16_t SQLSMALLINT;
typedef uint16_t SQLUSMALLINT;
typedef int32_t SQLINTEGER;
typedef uint32_t SQLUINTEGER;
typedef intptr_t SQLLEN;
typedef uintptr_t SQLULEN;
typedef SQLSMALLINT SQLRETURN;
typedef void *SQLPOINTER;
typedef void *SQLHANDLE;
typedef SQLHANDLE SQLHENV;
typedef SQLHANDLE SQLHDBC;
typedef SQLHANDLE SQLHSTMT;
typedef SQLHANDLE SQLHDESC;
typedef void *SQLHWND;
typedef double SQLDOUBLE;
typedef float SQLREAL;
typedef uint16_t SQLSETPOSIROW;

typedef struct { SQLSMALLINT year; SQLUSMALLINT month, day; } SQL_DATE_STRUCT;
typedef struct { SQLUSMALLINT hour, minute, second; } SQL_TIME_STRUCT;
typedef struct {
    SQLSMALLINT year; SQLUSMALLINT month, day, hour, minute, second;
    SQLUINTEGER fraction;
} SQL_TIMESTAMP_STRUCT;

#define SQL_SUCCEEDED(rc) (((rc) & ~1) == 0)
#define SQL_LEN_DATA_AT_EXEC(length) (-(length) + SQL_LEN_DATA_AT_EXEC_OFFSET)

#include "odbc_compat_constants.h"

#endif
