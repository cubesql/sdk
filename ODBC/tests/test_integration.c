#include "cubesql_odbc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

SQLRETURN SQL_API SQLAllocHandle(SQLSMALLINT, SQLHANDLE, SQLHANDLE *);
SQLRETURN SQL_API SQLFreeHandle(SQLSMALLINT, SQLHANDLE);
SQLRETURN SQL_API SQLSetEnvAttr(SQLHENV, SQLINTEGER, SQLPOINTER, SQLINTEGER);
SQLRETURN SQL_API SQLDriverConnect(SQLHDBC, SQLHWND, SQLCHAR *, SQLSMALLINT,
    SQLCHAR *, SQLSMALLINT, SQLSMALLINT *, SQLUSMALLINT);
SQLRETURN SQL_API SQLDisconnect(SQLHDBC);
SQLRETURN SQL_API SQLExecDirect(SQLHSTMT, SQLCHAR *, SQLINTEGER);
SQLRETURN SQL_API SQLPrepare(SQLHSTMT, SQLCHAR *, SQLINTEGER);
SQLRETURN SQL_API SQLExecute(SQLHSTMT);
SQLRETURN SQL_API SQLBindParameter(SQLHSTMT, SQLUSMALLINT, SQLSMALLINT,
    SQLSMALLINT, SQLSMALLINT, SQLULEN, SQLSMALLINT, SQLPOINTER, SQLLEN, SQLLEN *);
SQLRETURN SQL_API SQLBindCol(SQLHSTMT, SQLUSMALLINT, SQLSMALLINT, SQLPOINTER, SQLLEN, SQLLEN *);
SQLRETURN SQL_API SQLFetch(SQLHSTMT);
SQLRETURN SQL_API SQLFetchScroll(SQLHSTMT, SQLSMALLINT, SQLLEN);
SQLRETURN SQL_API SQLGetData(SQLHSTMT, SQLUSMALLINT, SQLSMALLINT, SQLPOINTER, SQLLEN, SQLLEN *);
SQLRETURN SQL_API SQLNumResultCols(SQLHSTMT, SQLSMALLINT *);
SQLRETURN SQL_API SQLDescribeCol(SQLHSTMT, SQLUSMALLINT, SQLCHAR *, SQLSMALLINT,
    SQLSMALLINT *, SQLSMALLINT *, SQLULEN *, SQLSMALLINT *, SQLSMALLINT *);
SQLRETURN SQL_API SQLSetConnectAttr(SQLHDBC, SQLINTEGER, SQLPOINTER, SQLINTEGER);
SQLRETURN SQL_API SQLEndTran(SQLSMALLINT, SQLHANDLE, SQLSMALLINT);
SQLRETURN SQL_API SQLFreeStmt(SQLHSTMT, SQLUSMALLINT);
SQLRETURN SQL_API SQLTables(SQLHSTMT, SQLCHAR *, SQLSMALLINT, SQLCHAR *, SQLSMALLINT,
    SQLCHAR *, SQLSMALLINT, SQLCHAR *, SQLSMALLINT);
SQLRETURN SQL_API SQLColumns(SQLHSTMT, SQLCHAR *, SQLSMALLINT, SQLCHAR *, SQLSMALLINT,
    SQLCHAR *, SQLSMALLINT, SQLCHAR *, SQLSMALLINT);
SQLRETURN SQL_API SQLPrimaryKeys(SQLHSTMT, SQLCHAR *, SQLSMALLINT, SQLCHAR *, SQLSMALLINT,
    SQLCHAR *, SQLSMALLINT);
SQLRETURN SQL_API SQLStatistics(SQLHSTMT, SQLCHAR *, SQLSMALLINT, SQLCHAR *, SQLSMALLINT,
    SQLCHAR *, SQLSMALLINT, SQLUSMALLINT, SQLUSMALLINT);
SQLRETURN SQL_API SQLGetTypeInfo(SQLHSTMT, SQLSMALLINT);
SQLRETURN SQL_API SQLGetDiagRec(SQLSMALLINT, SQLHANDLE, SQLSMALLINT, SQLCHAR *,
    SQLINTEGER *, SQLCHAR *, SQLSMALLINT, SQLSMALLINT *);
SQLRETURN SQL_API SQLParamData(SQLHSTMT, SQLPOINTER *);
SQLRETURN SQL_API SQLPutData(SQLHSTMT, SQLPOINTER, SQLLEN);

static int failures = 0;

static void print_diag(SQLSMALLINT type, SQLHANDLE handle) {
    SQLCHAR state[6], message[512]; SQLINTEGER native; SQLSMALLINT len;
    SQLSMALLINT i = 1;
    while (SQLGetDiagRec(type, handle, i++, state, &native, message,
                         sizeof(message), &len) == SQL_SUCCESS)
        fprintf(stderr, "      [%s] %s (%d)\n", state, message, (int)native);
}

#define CHECK(handle_type, handle, expr) do { \
    SQLRETURN check_rc = (expr); \
    if (!SQL_SUCCEEDED(check_rc)) { \
        fprintf(stderr, "FAIL line %d: %s -> %d\n", __LINE__, #expr, check_rc); \
        print_diag((handle_type), (handle)); failures++; goto cleanup; \
    } \
} while (0)

#define VERIFY(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); failures++; goto cleanup; \
} } while (0)

static int count_rows(SQLHSTMT stmt) {
    int rows = 0; SQLRETURN rc;
    while ((rc = SQLFetch(stmt)) == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO) rows++;
    if (rc != SQL_NO_DATA) {
        print_diag(SQL_HANDLE_STMT, stmt);
        return -1;
    }
    return rows;
}

int main(void) {
    SQLHENV env = SQL_NULL_HENV; SQLHDBC dbc = SQL_NULL_HDBC;
    SQLHSTMT stmt = SQL_NULL_HSTMT; SQLRETURN rc;
    const char *host = getenv("CUBESQL_ODBC_HOST");
    const char *port = getenv("CUBESQL_ODBC_PORT");
    const char *user = getenv("CUBESQL_ODBC_USER");
    const char *pass = getenv("CUBESQL_ODBC_PASSWORD");
    char conn[1024], out[1024], text[64], chunk[5];
    SQLSMALLINT outlen, cols, namelen, dtype, scale, nullable;
    SQLULEN size; SQLLEN ind1 = 0, ind2 = SQL_NTS, got = 0;
    int id = 7; char *name = "abcdefghij"; SQLPOINTER token = NULL;

    if (!host) host = "127.0.0.1"; if (!port) port = "4430";
    if (!user) user = "admin"; if (!pass) pass = "admin";
    snprintf(conn, sizeof(conn),
        "DRIVER={CubeSQL ODBC Driver};SERVER={%s};PORT=%s;UID={%s};PWD={%s};ENCRYPTION=NONE;TIMEOUT=12;",
        host, port, user, pass);

    CHECK(SQL_HANDLE_ENV, env, SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env));
    CHECK(SQL_HANDLE_ENV, env, SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION,
        (SQLPOINTER)(uintptr_t)SQL_OV_ODBC3_80, 0));
    CHECK(SQL_HANDLE_ENV, env, SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc));
    CHECK(SQL_HANDLE_DBC, dbc, SQLDriverConnect(dbc, NULL, (SQLCHAR *)conn, SQL_NTS,
        (SQLCHAR *)out, sizeof(out), &outlen, SQL_DRIVER_NOPROMPT));
    CHECK(SQL_HANDLE_DBC, dbc, SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt));

    /* Registration is deliberately opt-in so a normal integration run can
       never replace the registration on an existing CubeSQL installation. */
    if (getenv("CUBESQL_ODBC_REGISTER_TEST_SERVER")) {
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SET REGISTRATION TO 'SQLabs srl' WITH KEY "
                       "'CSQL75ZZ-PPJHAG9L-27X2W3C4-8DX6BAXX-35XBX46W';",
            SQL_NTS));
    }

    CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"CREATE DATABASE odbc_integration.db IF NOT EXISTS;", SQL_NTS));
    CHECK(SQL_HANDLE_DBC, dbc, SQLSetConnectAttr(dbc, SQL_ATTR_CURRENT_CATALOG,
        (SQLPOINTER)"odbc_integration.db", SQL_NTS));
    CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS odbc_driver_test;", SQL_NTS));
    CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"CREATE TABLE odbc_driver_test(id INTEGER PRIMARY KEY,name TEXT,payload BLOB);", SQL_NTS));

    CHECK(SQL_HANDLE_STMT, stmt, SQLPrepare(stmt,
        (SQLCHAR *)"INSERT INTO odbc_driver_test VALUES(?,?,?);", SQL_NTS));
    CHECK(SQL_HANDLE_STMT, stmt, SQLBindParameter(stmt, 1, SQL_PARAM_INPUT,
        SQL_C_LONG, SQL_INTEGER, 10, 0, &id, sizeof(id), &ind1));
    CHECK(SQL_HANDLE_STMT, stmt, SQLBindParameter(stmt, 2, SQL_PARAM_INPUT,
        SQL_C_CHAR, SQL_VARCHAR, 64, 0, name, 11, &ind2));
    {
        char blob[] = {0, 1, 2, 3}; SQLLEN bloblen = 4;
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindParameter(stmt, 3, SQL_PARAM_INPUT,
            SQL_C_BINARY, SQL_VARBINARY, 4, 0, blob, sizeof(blob), &bloblen));
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecute(stmt));
    }

    CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"SELECT id,name,payload FROM odbc_driver_test ORDER BY id;", SQL_NTS));
    CHECK(SQL_HANDLE_STMT, stmt, SQLNumResultCols(stmt, &cols)); VERIFY(cols == 3);
    CHECK(SQL_HANDLE_STMT, stmt, SQLDescribeCol(stmt, 2, (SQLCHAR *)text, sizeof(text),
        &namelen, &dtype, &size, &scale, &nullable)); VERIFY(!strcmp(text, "name"));
    memset(text, 0, sizeof(text));
    CHECK(SQL_HANDLE_STMT, stmt, SQLBindCol(stmt, 1, SQL_C_LONG, &id, sizeof(id), &got));
    CHECK(SQL_HANDLE_STMT, stmt, SQLBindCol(stmt, 2, SQL_C_CHAR, text, sizeof(text), &got));
    CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt)); VERIFY(id == 7 && !strcmp(text, "abcdefghij"));
    CHECK(SQL_HANDLE_STMT, stmt, SQLFetchScroll(stmt, SQL_FETCH_FIRST, 0));
    rc = SQLGetData(stmt, 2, SQL_C_CHAR, chunk, sizeof(chunk), &got);
    VERIFY(rc == SQL_SUCCESS_WITH_INFO && !strcmp(chunk, "abcd") && got == 10);
    CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 2, SQL_C_CHAR, chunk, sizeof(chunk), &got));
    VERIFY(!strcmp(chunk, "efgh"));

    CHECK(SQL_HANDLE_DBC, dbc, SQLSetConnectAttr(dbc, SQL_ATTR_AUTOCOMMIT,
        (SQLPOINTER)(uintptr_t)SQL_AUTOCOMMIT_OFF, 0));
    CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"INSERT INTO odbc_driver_test VALUES(8,'rollback',NULL);", SQL_NTS));
    CHECK(SQL_HANDLE_DBC, dbc, SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK));
    CHECK(SQL_HANDLE_DBC, dbc, SQLSetConnectAttr(dbc, SQL_ATTR_AUTOCOMMIT,
        (SQLPOINTER)(uintptr_t)SQL_AUTOCOMMIT_ON, 0));
    CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"SELECT id FROM odbc_driver_test WHERE id=8;", SQL_NTS));
    VERIFY(count_rows(stmt) == 0);

    CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_UNBIND));
    CHECK(SQL_HANDLE_STMT, stmt, SQLTables(stmt, NULL, 0, NULL, 0,
        (SQLCHAR *)"odbc_driver_test", SQL_NTS, (SQLCHAR *)"TABLE", SQL_NTS));
    VERIFY(count_rows(stmt) == 1);
    CHECK(SQL_HANDLE_STMT, stmt, SQLColumns(stmt, NULL, 0, NULL, 0,
        (SQLCHAR *)"odbc_driver_test", SQL_NTS, (SQLCHAR *)"%", SQL_NTS));
    VERIFY(count_rows(stmt) == 3);
    CHECK(SQL_HANDLE_STMT, stmt, SQLPrimaryKeys(stmt, NULL, 0, NULL, 0,
        (SQLCHAR *)"odbc_driver_test", SQL_NTS)); VERIFY(count_rows(stmt) == 1);
    CHECK(SQL_HANDLE_STMT, stmt, SQLStatistics(stmt, NULL, 0, NULL, 0,
        (SQLCHAR *)"odbc_driver_test", SQL_NTS, SQL_INDEX_ALL, SQL_QUICK));
    VERIFY(count_rows(stmt) >= 0);
    CHECK(SQL_HANDLE_STMT, stmt, SQLGetTypeInfo(stmt, SQL_ALL_TYPES));
    VERIFY(count_rows(stmt) >= 8);

    rc = SQLExecDirect(stmt, (SQLCHAR *)"THIS IS NOT SQL", SQL_NTS);
    VERIFY(rc == SQL_ERROR);
    CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt, (SQLCHAR *)"SELECT 42;", SQL_NTS));
    CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
    CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, text, sizeof(text), &got));
    VERIFY(!strcmp(text, "42"));

    CHECK(SQL_HANDLE_STMT, stmt, SQLPrepare(stmt,
        (SQLCHAR *)"INSERT INTO odbc_driver_test VALUES(9,?,NULL);", SQL_NTS));
    ind2 = SQL_DATA_AT_EXEC; name = "data-token";
    CHECK(SQL_HANDLE_STMT, stmt, SQLBindParameter(stmt, 1, SQL_PARAM_INPUT,
        SQL_C_CHAR, SQL_VARCHAR, 64, 0, name, 0, &ind2));
    VERIFY(SQLExecute(stmt) == SQL_NEED_DATA);
    VERIFY(SQLParamData(stmt, &token) == SQL_NEED_DATA && token == name);
    CHECK(SQL_HANDLE_STMT, stmt, SQLPutData(stmt, (SQLPOINTER)"streamed", 8));
    CHECK(SQL_HANDLE_STMT, stmt, SQLParamData(stmt, &token));

    printf("CubeSQL ODBC integration: PASS\n");

cleanup:
    if (stmt) { SQLFreeStmt(stmt, SQL_CLOSE); SQLFreeHandle(SQL_HANDLE_STMT, stmt); }
    if (dbc) { SQLDisconnect(dbc); SQLFreeHandle(SQL_HANDLE_DBC, dbc); }
    if (env) SQLFreeHandle(SQL_HANDLE_ENV, env);
    return failures ? 1 : 0;
}
