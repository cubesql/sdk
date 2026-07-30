#include "cubesql_odbc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

SQLRETURN SQL_API SQLAllocHandle(SQLSMALLINT, SQLHANDLE, SQLHANDLE *);
SQLRETURN SQL_API SQLFreeHandle(SQLSMALLINT, SQLHANDLE);
SQLRETURN SQL_API SQLSetEnvAttr(SQLHENV, SQLINTEGER, SQLPOINTER, SQLINTEGER);
SQLRETURN SQL_API SQLGetEnvAttr(SQLHENV, SQLINTEGER, SQLPOINTER, SQLINTEGER, SQLINTEGER *);
SQLRETURN SQL_API SQLDriverConnect(SQLHDBC, SQLHWND, SQLCHAR *, SQLSMALLINT,
    SQLCHAR *, SQLSMALLINT, SQLSMALLINT *, SQLUSMALLINT);
SQLRETURN SQL_API SQLGetDiagRec(SQLSMALLINT, SQLHANDLE, SQLSMALLINT, SQLCHAR *,
    SQLINTEGER *, SQLCHAR *, SQLSMALLINT, SQLSMALLINT *);

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", \
    __FILE__, __LINE__, #x); return 1; } } while (0)

int main(void) {
    SQLHENV env = SQL_NULL_HENV; SQLHDBC dbc = SQL_NULL_HDBC;
    SQLINTEGER version = 0, out_len = 0, native = 0; SQLSMALLINT len = 0;
    SQLCHAR state[6], message[512]; SQLRETURN rc;
    SQLWCHAR sample[] = {'c', 'a', 'f', 0x00e9, 0};
    char *utf8;

    REQUIRE(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env) == SQL_SUCCESS);
    REQUIRE(SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION,
        (SQLPOINTER)(uintptr_t)SQL_OV_ODBC3_80, 0) == SQL_SUCCESS);
    REQUIRE(SQLGetEnvAttr(env, SQL_ATTR_ODBC_VERSION, &version,
        sizeof(version), &out_len) == SQL_SUCCESS);
    REQUIRE(version == SQL_OV_ODBC3_80);
    REQUIRE(SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc) == SQL_SUCCESS);

    rc = SQLDriverConnect(dbc, NULL, (SQLCHAR *)"BROKEN", SQL_NTS,
        NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    REQUIRE(rc == SQL_ERROR);
    REQUIRE(SQLGetDiagRec(SQL_HANDLE_DBC, dbc, 1, state, &native, message,
        sizeof(message), &len) == SQL_SUCCESS);
    REQUIRE(!strcmp((char *)state, "IM012"));

    rc = SQLDriverConnect(dbc, NULL,
        (SQLCHAR *)"SERVER=localhost;PORT=4430;", SQL_NTS,
        NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    REQUIRE(rc == SQL_ERROR);
    REQUIRE(SQLGetDiagRec(SQL_HANDLE_DBC, dbc, 1, state, &native, message,
        sizeof(message), &len) == SQL_SUCCESS);
    REQUIRE(!strcmp((char *)state, "28000"));

    utf8 = cs_utf16_to_utf8(sample, SQL_NTS);
    REQUIRE(utf8 != NULL && !strcmp(utf8, "caf\xc3\xa9"));
    free(utf8);

    REQUIRE(SQLFreeHandle(SQL_HANDLE_DBC, dbc) == SQL_SUCCESS);
    REQUIRE(SQLFreeHandle(SQL_HANDLE_ENV, env) == SQL_SUCCESS);
    puts("CubeSQL ODBC core: PASS");
    return 0;
}
