#define ODBCVER 0x0380
#include <windows.h>
#include <sql.h>
#include <sqlext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void diag(SQLSMALLINT type, SQLHANDLE handle) {
    SQLCHAR state[6], message[512]; SQLINTEGER native; SQLSMALLINT len, i = 1;
    while (SQLGetDiagRecA(type, handle, i++, state, &native, message,
                          sizeof(message), &len) == SQL_SUCCESS)
        fprintf(stderr, "[%s] %s (%ld)\n", state, message, (long)native);
}

#define ODBC(call, type, handle) do { SQLRETURN rc_ = (call); if (!SQL_SUCCEEDED(rc_)) { \
    fprintf(stderr, "%s failed: %d\n", #call, rc_); diag(type, handle); goto fail; } } while (0)

int main(void) {
    SQLHENV env = SQL_NULL_HENV; SQLHDBC dbc = SQL_NULL_HDBC; SQLHSTMT stmt = SQL_NULL_HSTMT;
    SQLCHAR value[128], *connection = (SQLCHAR *)getenv("CUBESQL_ODBC_CONNECTION_STRING");
    SQLINTEGER answer = 0; SQLLEN indicator = 0;
    if (!connection) {
        fprintf(stderr, "Set CUBESQL_ODBC_CONNECTION_STRING to run the Windows Driver Manager smoke test.\n");
        return 2;
    }
    ODBC(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env), SQL_HANDLE_ENV, env);
    ODBC(SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3_80, 0), SQL_HANDLE_ENV, env);
    ODBC(SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc), SQL_HANDLE_ENV, env);
    ODBC(SQLDriverConnectA(dbc, NULL, connection, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT), SQL_HANDLE_DBC, dbc);
    ODBC(SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt), SQL_HANDLE_DBC, dbc);
    if (getenv("CUBESQL_ODBC_REGISTER_TEST_SERVER")) {
        ODBC(SQLExecDirectA(stmt,
            (SQLCHAR *)"SET REGISTRATION TO 'SQLabs srl' WITH KEY "
                       "'CSQL75ZZ-PPJHAG9L-27X2W3C4-8DX6BAXX-35XBX46W';",
            SQL_NTS), SQL_HANDLE_STMT, stmt);
    }
    ODBC(SQLExecDirectA(stmt,
        (SQLCHAR *)"CREATE DATABASE odbc_smoke.db IF NOT EXISTS;", SQL_NTS),
        SQL_HANDLE_STMT, stmt);
    ODBC(SQLSetConnectAttrA(dbc, SQL_ATTR_CURRENT_CATALOG,
        (SQLPOINTER)"odbc_smoke.db", SQL_NTS), SQL_HANDLE_DBC, dbc);
    ODBC(SQLExecDirectA(stmt, (SQLCHAR *)"SELECT 'CubeSQL ODBC', 42;", SQL_NTS), SQL_HANDLE_STMT, stmt);
    ODBC(SQLFetch(stmt), SQL_HANDLE_STMT, stmt);
    ODBC(SQLGetData(stmt, 1, SQL_C_CHAR, value, sizeof(value), &indicator), SQL_HANDLE_STMT, stmt);
    ODBC(SQLGetData(stmt, 2, SQL_C_SLONG, &answer, sizeof(answer), &indicator), SQL_HANDLE_STMT, stmt);
    if (strcmp((char *)value, "CubeSQL ODBC") != 0 || answer != 42) {
        fprintf(stderr, "Unexpected result: '%s', %ld\n", value, (long)answer);
        goto fail;
    }
    printf("%s: PASS\n", value);
    SQLFreeHandle(SQL_HANDLE_STMT, stmt); SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc); SQLFreeHandle(SQL_HANDLE_ENV, env); return 0;
fail:
    if (stmt) SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    if (dbc) { SQLDisconnect(dbc); SQLFreeHandle(SQL_HANDLE_DBC, dbc); }
    if (env) SQLFreeHandle(SQL_HANDLE_ENV, env);
    return 1;
}
