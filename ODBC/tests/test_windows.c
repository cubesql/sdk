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

#define ODBC(call, type, handle) do { \
    SQLRETURN rc_; \
    fprintf(stderr, "ODBC BEGIN: %s\n", #call); fflush(stderr); \
    rc_ = (call); \
    fprintf(stderr, "ODBC END: %s -> %d\n", #call, rc_); fflush(stderr); \
    if (!SQL_SUCCEEDED(rc_)) { \
        diag(type, handle); goto fail; \
    } \
} while (0)

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
    ODBC(SQLExecDirectA(stmt,
        (SQLCHAR *)"USE DATABASE odbc_smoke.db;", SQL_NTS),
        SQL_HANDLE_STMT, stmt);
    ODBC(SQLExecDirectA(stmt, (SQLCHAR *)"SELECT 'CubeSQL ODBC', 42;", SQL_NTS), SQL_HANDLE_STMT, stmt);
    ODBC(SQLFetch(stmt), SQL_HANDLE_STMT, stmt);
    ODBC(SQLGetData(stmt, 1, SQL_C_CHAR, value, sizeof(value), &indicator), SQL_HANDLE_STMT, stmt);
    ODBC(SQLGetData(stmt, 2, SQL_C_SLONG, &answer, sizeof(answer), &indicator), SQL_HANDLE_STMT, stmt);
    if (strcmp((char *)value, "CubeSQL ODBC") != 0 || answer != 42) {
        fprintf(stderr, "Unexpected result: '%s', %ld\n", value, (long)answer);
        goto fail;
    }
    ODBC(SQLFreeStmt(stmt, SQL_CLOSE), SQL_HANDLE_STMT, stmt);

    /*
     * The rest exercises, through the real Driver Manager, the behaviour that
     * the first release did not provide. These are the paths the native suites
     * cannot cover because they bypass the Driver Manager entirely.
     */
    {
        /* The driver must report a version and identify itself. */
        SQLCHAR driver_ver[64] = "", driver_name[128] = "", dbms[64] = "";
        SQLSMALLINT len = 0;
        ODBC(SQLGetInfoA(dbc, SQL_DRIVER_VER, driver_ver, sizeof(driver_ver), &len),
             SQL_HANDLE_DBC, dbc);
        ODBC(SQLGetInfoA(dbc, SQL_DRIVER_NAME, driver_name, sizeof(driver_name), &len),
             SQL_HANDLE_DBC, dbc);
        ODBC(SQLGetInfoA(dbc, SQL_DBMS_NAME, dbms, sizeof(dbms), &len), SQL_HANDLE_DBC, dbc);
        fprintf(stderr, "SQL_DRIVER_VER=%s SQL_DRIVER_NAME=%s SQL_DBMS_NAME=%s\n",
                driver_ver, driver_name, dbms);
        if (!driver_ver[0] || driver_ver[0] == '0') {
            fprintf(stderr, "SQL_DRIVER_VER is missing or zero.\n");
            goto fail;
        }
    }
    {
        /*
         * Every InfoType an ODBC consumer routinely asks for. The Driver
         * Manager forwards these straight to the driver, and the first release
         * failed most of them with HY096, which is what made Excel and ADO
         * give up during connect.
         */
        static const SQLUSMALLINT infos[] = {
            SQL_STRING_FUNCTIONS, SQL_NUMERIC_FUNCTIONS, SQL_TIMEDATE_FUNCTIONS,
            SQL_SYSTEM_FUNCTIONS, SQL_CONVERT_FUNCTIONS, SQL_KEYWORDS,
            SQL_STATIC_CURSOR_ATTRIBUTES1, SQL_STATIC_CURSOR_ATTRIBUTES2,
            SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES1, SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES2,
            SQL_DYNAMIC_CURSOR_ATTRIBUTES1, SQL_KEYSET_CURSOR_ATTRIBUTES1,
            SQL_FILE_USAGE, SQL_ACTIVE_ENVIRONMENTS, SQL_OJ_CAPABILITIES,
            SQL_SUBQUERIES, SQL_UNION, SQL_GROUP_BY, SQL_CORRELATION_NAME,
            SQL_NON_NULLABLE_COLUMNS, SQL_POS_OPERATIONS, SQL_BOOKMARK_PERSISTENCE,
            SQL_SCROLL_CONCURRENCY, SQL_CREATE_TABLE, SQL_DROP_TABLE,
            SQL_INDEX_KEYWORDS, SQL_AGGREGATE_FUNCTIONS, SQL_CATALOG_USAGE,
            SQL_ODBC_INTERFACE_CONFORMANCE, SQL_INSERT_STATEMENT
        };
        char buffer[4096]; SQLSMALLINT len = 0; size_t i; int bad = 0;
        for (i = 0; i < sizeof(infos) / sizeof(infos[0]); i++) {
            SQLRETURN rc = SQLGetInfoA(dbc, infos[i], buffer, sizeof(buffer), &len);
            if (!SQL_SUCCEEDED(rc)) {
                fprintf(stderr, "SQLGetInfo(%u) -> %d\n", (unsigned)infos[i], rc);
                bad++;
            }
        }
        if (bad) { fprintf(stderr, "%d InfoTypes were rejected.\n", bad); goto fail; }
    }
    {
        /* Block fetch: what Excel and Power Query use by default. */
        SQLINTEGER ids[4]; SQLLEN ind[4]; SQLULEN fetched = 0; SQLUSMALLINT status[4];
        SQLULEN total = 0;
        ODBC(SQLSetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE, (SQLPOINTER)(SQLULEN)4, 0),
             SQL_HANDLE_STMT, stmt);
        ODBC(SQLSetStmtAttr(stmt, SQL_ATTR_ROWS_FETCHED_PTR, &fetched, 0), SQL_HANDLE_STMT, stmt);
        ODBC(SQLSetStmtAttr(stmt, SQL_ATTR_ROW_STATUS_PTR, status, 0), SQL_HANDLE_STMT, stmt);
        ODBC(SQLExecDirectA(stmt,
            (SQLCHAR *)"SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL "
                       "SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6;", SQL_NTS),
            SQL_HANDLE_STMT, stmt);
        ODBC(SQLBindCol(stmt, 1, SQL_C_SLONG, ids, sizeof(ids[0]), ind), SQL_HANDLE_STMT, stmt);
        while (SQL_SUCCEEDED(SQLFetch(stmt))) total += fetched;
        if (total != 6) {
            fprintf(stderr, "Block fetch returned %lu rows, expected 6.\n", (unsigned long)total);
            goto fail;
        }
        ODBC(SQLFreeStmt(stmt, SQL_UNBIND), SQL_HANDLE_STMT, stmt);
        ODBC(SQLFreeStmt(stmt, SQL_CLOSE), SQL_HANDLE_STMT, stmt);
        ODBC(SQLSetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE, (SQLPOINTER)(SQLULEN)1, 0),
             SQL_HANDLE_STMT, stmt);
        ODBC(SQLSetStmtAttr(stmt, SQL_ATTR_ROWS_FETCHED_PTR, NULL, 0), SQL_HANDLE_STMT, stmt);
        ODBC(SQLSetStmtAttr(stmt, SQL_ATTR_ROW_STATUS_PTR, NULL, 0), SQL_HANDLE_STMT, stmt);
    }
    {
        /* Attributes consumers set unconditionally must not be fatal. */
        ODBC(SQLSetStmtAttr(stmt, SQL_ATTR_NOSCAN, (SQLPOINTER)(SQLULEN)SQL_NOSCAN_OFF, 0),
             SQL_HANDLE_STMT, stmt);
        ODBC(SQLSetStmtAttr(stmt, SQL_ATTR_METADATA_ID, (SQLPOINTER)(SQLULEN)SQL_FALSE, 0),
             SQL_HANDLE_STMT, stmt);
        ODBC(SQLSetConnectAttr(dbc, SQL_ATTR_METADATA_ID, (SQLPOINTER)(SQLULEN)SQL_FALSE, 0),
             SQL_HANDLE_DBC, dbc);
    }
    {
        /* Escape sequence translation. */
        SQLCHAR text[64] = "";
        ODBC(SQLExecDirectA(stmt, (SQLCHAR *)"SELECT {fn UCASE('cubesql')};", SQL_NTS),
             SQL_HANDLE_STMT, stmt);
        ODBC(SQLFetch(stmt), SQL_HANDLE_STMT, stmt);
        ODBC(SQLGetData(stmt, 1, SQL_C_CHAR, text, sizeof(text), &indicator),
             SQL_HANDLE_STMT, stmt);
        if (strcmp((char *)text, "CUBESQL") != 0) {
            fprintf(stderr, "Escape translation produced '%s'.\n", text);
            goto fail;
        }
        ODBC(SQLFreeStmt(stmt, SQL_CLOSE), SQL_HANDLE_STMT, stmt);
    }
    {
        /*
         * SQLDisconnect must free the statement, so freeing the connection
         * afterwards succeeds. This sequence used to fail with HY010.
         */
        SQLHDBC second = SQL_NULL_HDBC; SQLHSTMT extra = SQL_NULL_HSTMT;
        ODBC(SQLAllocHandle(SQL_HANDLE_DBC, env, &second), SQL_HANDLE_ENV, env);
        ODBC(SQLDriverConnectA(second, NULL, connection, SQL_NTS, NULL, 0, NULL,
                               SQL_DRIVER_NOPROMPT), SQL_HANDLE_DBC, second);
        ODBC(SQLAllocHandle(SQL_HANDLE_STMT, second, &extra), SQL_HANDLE_DBC, second);
        ODBC(SQLDisconnect(second), SQL_HANDLE_DBC, second);
        ODBC(SQLFreeHandle(SQL_HANDLE_DBC, second), SQL_HANDLE_DBC, second);
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
