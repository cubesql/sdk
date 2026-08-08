/*
 * Conformance suite for the behaviour ODBC consumers depend on but the first
 * driver release did not provide: block (rowset) fetch, parameter arrays,
 * tolerant attribute handling, correct disconnect semantics, a complete
 * SQLGetInfo, and safe concurrent use of one connection.
 *
 * Runs against a live CubeSQL server, like test_integration.c.
 */
#include "cubesql_odbc.h"

#include <pthread.h>
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
SQLRETURN SQL_API SQLExtendedFetch(SQLHSTMT, SQLUSMALLINT, SQLLEN, SQLULEN *, SQLUSMALLINT *);
SQLRETURN SQL_API SQLGetData(SQLHSTMT, SQLUSMALLINT, SQLSMALLINT, SQLPOINTER, SQLLEN, SQLLEN *);
SQLRETURN SQL_API SQLSetConnectAttr(SQLHDBC, SQLINTEGER, SQLPOINTER, SQLINTEGER);
SQLRETURN SQL_API SQLGetConnectAttr(SQLHDBC, SQLINTEGER, SQLPOINTER, SQLINTEGER, SQLINTEGER *);
SQLRETURN SQL_API SQLSetStmtAttr(SQLHSTMT, SQLINTEGER, SQLPOINTER, SQLINTEGER);
SQLRETURN SQL_API SQLGetStmtAttr(SQLHSTMT, SQLINTEGER, SQLPOINTER, SQLINTEGER, SQLINTEGER *);
SQLRETURN SQL_API SQLGetInfo(SQLHDBC, SQLUSMALLINT, SQLPOINTER, SQLSMALLINT, SQLSMALLINT *);
SQLRETURN SQL_API SQLFreeStmt(SQLHSTMT, SQLUSMALLINT);
SQLRETURN SQL_API SQLCancel(SQLHSTMT);
SQLRETURN SQL_API SQLTables(SQLHSTMT, SQLCHAR *, SQLSMALLINT, SQLCHAR *, SQLSMALLINT,
    SQLCHAR *, SQLSMALLINT, SQLCHAR *, SQLSMALLINT);
SQLRETURN SQL_API SQLGetDiagRec(SQLSMALLINT, SQLHANDLE, SQLSMALLINT, SQLCHAR *,
    SQLINTEGER *, SQLCHAR *, SQLSMALLINT, SQLSMALLINT *);
SQLRETURN SQL_API SQLRowCount(SQLHSTMT, SQLLEN *);
SQLRETURN SQL_API SQLNativeSql(SQLHDBC, SQLCHAR *, SQLINTEGER, SQLCHAR *, SQLINTEGER, SQLINTEGER *);

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

#define ROWS 12
#define ROWSET 5

static char g_conn[1024];

static SQLRETURN connect_new(SQLHENV env, SQLHDBC *dbc) {
    char out[1024]; SQLSMALLINT outlen; SQLRETURN rc;
    rc = SQLAllocHandle(SQL_HANDLE_DBC, env, dbc);
    if (!SQL_SUCCEEDED(rc)) return rc;
    return SQLDriverConnect(*dbc, NULL, (SQLCHAR *)g_conn, SQL_NTS,
                            (SQLCHAR *)out, sizeof(out), &outlen, SQL_DRIVER_NOPROMPT);
}

/* Hammers one connection from a second thread to shake out missing locking. */
struct worker_arg { SQLHDBC dbc; int iterations; int errors; };

static void *worker(void *raw) {
    struct worker_arg *arg = (struct worker_arg *)raw;
    int i;
    for (i = 0; i < arg->iterations; i++) {
        SQLHSTMT stmt = SQL_NULL_HSTMT; SQLLEN ind = 0; int value = 0;
        if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, arg->dbc, &stmt))) { arg->errors++; continue; }
        if (!SQL_SUCCEEDED(SQLExecDirect(stmt,
                (SQLCHAR *)"SELECT count(*) FROM odbc_conformance;", SQL_NTS))) arg->errors++;
        else if (!SQL_SUCCEEDED(SQLBindCol(stmt, 1, SQL_C_LONG, &value, sizeof(value), &ind))) arg->errors++;
        else if (!SQL_SUCCEEDED(SQLFetch(stmt))) arg->errors++;
        else if (value != ROWS) arg->errors++;
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    }
    return NULL;
}

int main(void) {
    SQLHENV env = SQL_NULL_HENV; SQLHDBC dbc = SQL_NULL_HDBC;
    SQLHSTMT stmt = SQL_NULL_HSTMT; SQLRETURN rc;
    const char *host = getenv("CUBESQL_ODBC_HOST");
    const char *port = getenv("CUBESQL_ODBC_PORT");
    const char *user = getenv("CUBESQL_ODBC_USER");
    const char *pass = getenv("CUBESQL_ODBC_PASSWORD");
    char out[1024];
    SQLSMALLINT outlen;
    int i;

    if (!host) host = "127.0.0.1"; if (!port) port = "4430";
    if (!user) user = "admin"; if (!pass) pass = "admin";
    snprintf(g_conn, sizeof(g_conn),
        "DRIVER={CubeSQL ODBC Driver};SERVER={%s};PORT=%s;UID={%s};PWD={%s};ENCRYPTION=NONE;TIMEOUT=12;",
        host, port, user, pass);

    CHECK(SQL_HANDLE_ENV, env, SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env));
    CHECK(SQL_HANDLE_ENV, env, SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION,
        (SQLPOINTER)(uintptr_t)SQL_OV_ODBC3_80, 0));
    CHECK(SQL_HANDLE_ENV, env, SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc));
    CHECK(SQL_HANDLE_DBC, dbc, SQLDriverConnect(dbc, NULL, (SQLCHAR *)g_conn, SQL_NTS,
        (SQLCHAR *)out, sizeof(out), &outlen, SQL_DRIVER_NOPROMPT));

    /*
     * The connection string handed back must never carry the password: the
     * Driver Manager returns it to the application, which often persists it.
     * (Checking for the literal password value would be ambiguous here because
     * the default test credentials use the same string for user and password.)
     */
    VERIFY(strstr(out, "PWD=") == NULL);
    VERIFY(strstr(out, "PWD ") == NULL);
    VERIFY(strstr(out, "PASSWORD") == NULL);

    CHECK(SQL_HANDLE_DBC, dbc, SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt));
    if (getenv("CUBESQL_ODBC_REGISTER_TEST_SERVER")) {
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SET REGISTRATION TO 'SQLabs srl' WITH KEY "
                       "'CSQL75ZZ-PPJHAG9L-27X2W3C4-8DX6BAXX-35XBX46W';", SQL_NTS));
    }
    CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"CREATE DATABASE odbc_conformance.db IF NOT EXISTS;", SQL_NTS));
    CHECK(SQL_HANDLE_DBC, dbc, SQLSetConnectAttr(dbc, SQL_ATTR_CURRENT_CATALOG,
        (SQLPOINTER)"odbc_conformance.db", SQL_NTS));
    CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS odbc_conformance;", SQL_NTS));
    CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"CREATE TABLE odbc_conformance(id INTEGER PRIMARY KEY, name TEXT);", SQL_NTS));

    /* ---- parameter arrays -------------------------------------------- */
    {
        int ids[ROWS]; char names[ROWS][16]; SQLLEN id_ind[ROWS], name_ind[ROWS];
        SQLULEN processed = 0; SQLUSMALLINT status[ROWS];
        for (i = 0; i < ROWS; i++) {
            ids[i] = i + 1;
            snprintf(names[i], sizeof(names[i]), "row-%02d", i + 1);
            id_ind[i] = 0; name_ind[i] = SQL_NTS;
        }
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_PARAMSET_SIZE,
            (SQLPOINTER)(uintptr_t)ROWS, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_PARAMS_PROCESSED_PTR, &processed, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_PARAM_STATUS_PTR, status, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLPrepare(stmt,
            (SQLCHAR *)"INSERT INTO odbc_conformance VALUES(?,?);", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindParameter(stmt, 1, SQL_PARAM_INPUT,
            SQL_C_LONG, SQL_INTEGER, 10, 0, ids, sizeof(ids[0]), id_ind));
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindParameter(stmt, 2, SQL_PARAM_INPUT,
            SQL_C_CHAR, SQL_VARCHAR, 15, 0, names, sizeof(names[0]), name_ind));
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecute(stmt));
        VERIFY(processed == ROWS);
        for (i = 0; i < ROWS; i++) VERIFY(status[i] == SQL_PARAM_SUCCESS);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_RESET_PARAMS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_PARAMSET_SIZE,
            (SQLPOINTER)(uintptr_t)1, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_PARAMS_PROCESSED_PTR, NULL, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_PARAM_STATUS_PTR, NULL, 0));
    }

    /* ---- column-wise rowset fetch ------------------------------------ */
    {
        int ids[ROWSET]; char names[ROWSET][16];
        SQLLEN id_ind[ROWSET], name_ind[ROWSET];
        SQLULEN fetched = 0; SQLUSMALLINT status[ROWSET];
        int total = 0, expect = 1;

        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE,
            (SQLPOINTER)(uintptr_t)ROWSET, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROWS_FETCHED_PTR, &fetched, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_STATUS_PTR, status, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id,name FROM odbc_conformance ORDER BY id;", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindCol(stmt, 1, SQL_C_LONG, ids, sizeof(ids[0]), id_ind));
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindCol(stmt, 2, SQL_C_CHAR, names, sizeof(names[0]), name_ind));
        while (SQL_SUCCEEDED(rc = SQLFetch(stmt))) {
            SQLULEN r;
            VERIFY(fetched >= 1 && fetched <= ROWSET);
            for (r = 0; r < fetched; r++) {
                char want[16];
                VERIFY(status[r] == SQL_ROW_SUCCESS);
                VERIFY(ids[r] == expect);
                snprintf(want, sizeof(want), "row-%02d", expect);
                VERIFY(!strcmp(names[r], want));
                expect++; total++;
            }
            /* Rows past the last one in a partial rowset must be marked. */
            for (r = fetched; r < ROWSET; r++) VERIFY(status[r] == SQL_ROW_NOROW);
        }
        VERIFY(rc == SQL_NO_DATA);
        VERIFY(total == ROWS);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_UNBIND));
    }

    /* ---- column-wise rowset with a zero BufferLength ------------------ */
    {
        /*
         * ODBC lets a fixed-length C type be bound with BufferLength 0. The
         * array stride then has to come from the C type: deriving it from
         * BufferLength would stack every row of the rowset on the first.
         */
        int ids[ROWSET]; SQLLEN ind[ROWSET];
        SQLULEN fetched = 0; SQLULEN r;

        memset(ids, 0, sizeof(ids));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE,
            (SQLPOINTER)(uintptr_t)ROWSET, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROWS_FETCHED_PTR, &fetched, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_STATUS_PTR, NULL, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id FROM odbc_conformance ORDER BY id;", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindCol(stmt, 1, SQL_C_LONG, ids, 0, ind));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        VERIFY(fetched == ROWSET);
        for (r = 0; r < fetched; r++) VERIFY(ids[r] == (int)(r + 1));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_UNBIND));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---- row-wise rowset fetch --------------------------------------- */
    {
        struct row { int id; SQLLEN id_ind; char name[16]; SQLLEN name_ind; };
        struct row rows[ROWSET];
        SQLULEN fetched = 0; int total = 0, expect = 1;

        memset(rows, 0, sizeof(rows));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_BIND_TYPE,
            (SQLPOINTER)(uintptr_t)sizeof(struct row), 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROWS_FETCHED_PTR, &fetched, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_STATUS_PTR, NULL, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id,name FROM odbc_conformance ORDER BY id;", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindCol(stmt, 1, SQL_C_LONG,
            &rows[0].id, sizeof(rows[0].id), &rows[0].id_ind));
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindCol(stmt, 2, SQL_C_CHAR,
            rows[0].name, sizeof(rows[0].name), &rows[0].name_ind));
        while (SQL_SUCCEEDED(rc = SQLFetch(stmt))) {
            SQLULEN r;
            for (r = 0; r < fetched; r++) {
                char want[16];
                VERIFY(rows[r].id == expect);
                snprintf(want, sizeof(want), "row-%02d", expect);
                VERIFY(!strcmp(rows[r].name, want));
                VERIFY(rows[r].name_ind == (SQLLEN)strlen(want));
                expect++; total++;
            }
        }
        VERIFY(rc == SQL_NO_DATA);
        VERIFY(total == ROWS);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_UNBIND));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_BIND_TYPE,
            (SQLPOINTER)(uintptr_t)SQL_BIND_BY_COLUMN, 0));
    }

    /* ---- scrolling over rowsets and SQLExtendedFetch ------------------ */
    {
        int ids[ROWSET]; SQLLEN id_ind[ROWSET];
        SQLULEN fetched = 0; SQLUSMALLINT status[ROWSET];

        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROWS_FETCHED_PTR, &fetched, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id FROM odbc_conformance ORDER BY id;", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindCol(stmt, 1, SQL_C_LONG, ids, sizeof(ids[0]), id_ind));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetchScroll(stmt, SQL_FETCH_LAST, 0));
        VERIFY(fetched == ROWSET && ids[0] == ROWS - ROWSET + 1 && ids[ROWSET - 1] == ROWS);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetchScroll(stmt, SQL_FETCH_FIRST, 0));
        VERIFY(fetched == ROWSET && ids[0] == 1);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetchScroll(stmt, SQL_FETCH_ABSOLUTE, 3));
        VERIFY(fetched == ROWSET && ids[0] == 3);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetchScroll(stmt, SQL_FETCH_PRIOR, 0));
        VERIFY(fetched >= 1 && ids[0] == 1);
        /* SQLExtendedFetch reports through its own pointers. */
        fetched = 999;
        CHECK(SQL_HANDLE_STMT, stmt, SQLExtendedFetch(stmt, SQL_FETCH_FIRST, 0, NULL, status));
        VERIFY(fetched == 999);
        VERIFY(status[0] == SQL_ROW_SUCCESS);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_UNBIND));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROWS_FETCHED_PTR, NULL, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE,
            (SQLPOINTER)(uintptr_t)1, 0));
    }

    /* ---- attributes every consumer sets must not be fatal ------------- */
    {
        SQLULEN value = 0;
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_NOSCAN,
            (SQLPOINTER)(uintptr_t)SQL_NOSCAN_ON, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_NOSCAN, &value, 0, NULL));
        VERIFY(value == SQL_NOSCAN_ON);
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_METADATA_ID,
            (SQLPOINTER)(uintptr_t)SQL_TRUE, 0));
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_METADATA_ID,
            (SQLPOINTER)(uintptr_t)SQL_FALSE, 0));
        CHECK(SQL_HANDLE_DBC, dbc, SQLSetConnectAttr(dbc, SQL_ATTR_METADATA_ID,
            (SQLPOINTER)(uintptr_t)SQL_FALSE, 0));
        CHECK(SQL_HANDLE_DBC, dbc, SQLSetConnectAttr(dbc, SQL_ATTR_QUIET_MODE, NULL, 0));
        CHECK(SQL_HANDLE_DBC, dbc, SQLSetConnectAttr(dbc, SQL_ATTR_ODBC_CURSORS,
            (SQLPOINTER)(uintptr_t)SQL_CUR_USE_DRIVER, 0));
        /* Substituted values are warnings, never hard errors. */
        rc = SQLSetStmtAttr(stmt, SQL_ATTR_CURSOR_TYPE,
            (SQLPOINTER)(uintptr_t)SQL_CURSOR_KEYSET_DRIVEN, 0);
        VERIFY(rc == SQL_SUCCESS_WITH_INFO);
        CHECK(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_CURSOR_TYPE, &value, 0, NULL));
        VERIFY(value == SQL_CURSOR_STATIC);
        rc = SQLSetStmtAttr(stmt, SQL_ATTR_CONCURRENCY,
            (SQLPOINTER)(uintptr_t)SQL_CONCUR_LOCK, 0);
        VERIFY(rc == SQL_SUCCESS_WITH_INFO);
        rc = SQLSetConnectAttr(dbc, SQL_ATTR_PACKET_SIZE, (SQLPOINTER)(uintptr_t)8192, 0);
        VERIFY(rc == SQL_SUCCESS_WITH_INFO);
        rc = SQLSetConnectAttr(dbc, SQL_ATTR_TXN_ISOLATION,
            (SQLPOINTER)(uintptr_t)SQL_TXN_READ_COMMITTED, 0);
        VERIFY(rc == SQL_SUCCESS_WITH_INFO);

        /* With SQL_NOSCAN_ON still set, escape sequences must reach the server
           untouched, which CubeSQL rejects. That proves the attribute is
           honoured rather than ignored. */
        rc = SQLExecDirect(stmt, (SQLCHAR *)"SELECT {fn UCASE('abc')};", SQL_NTS);
        VERIFY(rc == SQL_ERROR);
        CHECK(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_NOSCAN,
            (SQLPOINTER)(uintptr_t)SQL_NOSCAN_OFF, 0));
    }

    /* ---- SQLGetInfo must answer every InfoType the spec defines ------- */
    {
        static const SQLUSMALLINT required[] = {
            SQL_ACTIVE_ENVIRONMENTS, SQL_AGGREGATE_FUNCTIONS, SQL_ALTER_TABLE,
            SQL_BATCH_SUPPORT, SQL_BOOKMARK_PERSISTENCE, SQL_CATALOG_LOCATION,
            SQL_CATALOG_NAME, SQL_CATALOG_NAME_SEPARATOR, SQL_CATALOG_TERM,
            SQL_CATALOG_USAGE, SQL_COLUMN_ALIAS, SQL_CONCAT_NULL_BEHAVIOR,
            SQL_CONVERT_BIGINT, SQL_CONVERT_CHAR, SQL_CONVERT_DOUBLE,
            SQL_CONVERT_FUNCTIONS, SQL_CONVERT_INTEGER, SQL_CONVERT_LONGVARBINARY,
            SQL_CONVERT_LONGVARCHAR, SQL_CONVERT_VARCHAR, SQL_CONVERT_WCHAR,
            SQL_CORRELATION_NAME, SQL_CREATE_TABLE, SQL_CREATE_VIEW,
            SQL_CURSOR_COMMIT_BEHAVIOR, SQL_CURSOR_ROLLBACK_BEHAVIOR,
            SQL_CURSOR_SENSITIVITY, SQL_DATA_SOURCE_NAME, SQL_DATA_SOURCE_READ_ONLY,
            SQL_DATABASE_NAME, SQL_DBMS_NAME, SQL_DBMS_VER, SQL_DDL_INDEX,
            SQL_DEFAULT_TXN_ISOLATION, SQL_DESCRIBE_PARAMETER, SQL_DRIVER_NAME,
            SQL_DRIVER_ODBC_VER, SQL_DRIVER_VER, SQL_DROP_TABLE, SQL_DROP_VIEW,
            SQL_DYNAMIC_CURSOR_ATTRIBUTES1, SQL_DYNAMIC_CURSOR_ATTRIBUTES2,
            SQL_EXPRESSIONS_IN_ORDERBY, SQL_FILE_USAGE,
            SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES1, SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES2,
            SQL_GETDATA_EXTENSIONS, SQL_GROUP_BY, SQL_IDENTIFIER_CASE,
            SQL_IDENTIFIER_QUOTE_CHAR, SQL_INDEX_KEYWORDS, SQL_INFO_SCHEMA_VIEWS,
            SQL_INSERT_STATEMENT, SQL_INTEGRITY, SQL_KEYSET_CURSOR_ATTRIBUTES1,
            SQL_KEYSET_CURSOR_ATTRIBUTES2, SQL_KEYWORDS, SQL_LIKE_ESCAPE_CLAUSE,
            SQL_MAX_BINARY_LITERAL_LEN, SQL_MAX_CATALOG_NAME_LEN,
            SQL_MAX_CHAR_LITERAL_LEN, SQL_MAX_COLUMN_NAME_LEN,
            SQL_MAX_COLUMNS_IN_GROUP_BY, SQL_MAX_COLUMNS_IN_INDEX,
            SQL_MAX_COLUMNS_IN_ORDER_BY, SQL_MAX_COLUMNS_IN_SELECT,
            SQL_MAX_COLUMNS_IN_TABLE, SQL_MAX_CONCURRENT_ACTIVITIES,
            SQL_MAX_CURSOR_NAME_LEN, SQL_MAX_DRIVER_CONNECTIONS,
            SQL_MAX_IDENTIFIER_LEN, SQL_MAX_INDEX_SIZE, SQL_MAX_PROCEDURE_NAME_LEN,
            SQL_MAX_ROW_SIZE, SQL_MAX_ROW_SIZE_INCLUDES_LONG, SQL_MAX_SCHEMA_NAME_LEN,
            SQL_MAX_STATEMENT_LEN, SQL_MAX_TABLE_NAME_LEN, SQL_MAX_TABLES_IN_SELECT,
            SQL_MAX_USER_NAME_LEN, SQL_MULT_RESULT_SETS, SQL_MULTIPLE_ACTIVE_TXN,
            SQL_NEED_LONG_DATA_LEN, SQL_NON_NULLABLE_COLUMNS, SQL_NULL_COLLATION,
            SQL_NUMERIC_FUNCTIONS, SQL_ODBC_INTERFACE_CONFORMANCE, SQL_ODBC_VER,
            SQL_OJ_CAPABILITIES, SQL_ORDER_BY_COLUMNS_IN_SELECT, SQL_OUTER_JOINS,
            SQL_PARAM_ARRAY_ROW_COUNTS, SQL_PARAM_ARRAY_SELECTS, SQL_POS_OPERATIONS,
            SQL_PROCEDURE_TERM, SQL_PROCEDURES, SQL_QUOTED_IDENTIFIER_CASE,
            SQL_ROW_UPDATES, SQL_SCHEMA_TERM, SQL_SCHEMA_USAGE, SQL_SCROLL_OPTIONS,
            SQL_SEARCH_PATTERN_ESCAPE, SQL_SERVER_NAME, SQL_SPECIAL_CHARACTERS,
            SQL_SQL_CONFORMANCE, SQL_STATIC_CURSOR_ATTRIBUTES1,
            SQL_STATIC_CURSOR_ATTRIBUTES2, SQL_STRING_FUNCTIONS, SQL_SUBQUERIES,
            SQL_SYSTEM_FUNCTIONS, SQL_TABLE_TERM, SQL_TIMEDATE_ADD_INTERVALS,
            SQL_TIMEDATE_DIFF_INTERVALS, SQL_TIMEDATE_FUNCTIONS, SQL_TXN_CAPABLE,
            SQL_TXN_ISOLATION_OPTION, SQL_UNION, SQL_USER_NAME, SQL_XOPEN_CLI_YEAR
        };
        char buffer[4096]; SQLSMALLINT len; size_t k;
        for (k = 0; k < sizeof(required) / sizeof(required[0]); k++) {
            memset(buffer, 0, sizeof(buffer));
            rc = SQLGetInfo(dbc, required[k], buffer, sizeof(buffer), &len);
            if (!SQL_SUCCEEDED(rc)) {
                fprintf(stderr, "FAIL: SQLGetInfo(%u) returned %d\n",
                        (unsigned)required[k], rc);
                print_diag(SQL_HANDLE_DBC, dbc);
                failures++;
            }
        }
        VERIFY(failures == 0);
    }

    /* ---- non-ASCII round trip ----------------------------------------- */
    {
        /* "Grösse" and "Ærø" in UTF-8, written and read back through the
           SQL_C_CHAR path. On Windows this exercises the ANSI code page
           conversion; elsewhere SQL_C_CHAR is UTF-8 and the bytes pass
           through unchanged. Either way the value must survive intact. */
        /* Split so the 'e' cannot be absorbed into the preceding hex escape. */
        static const char sample[] = "Gr\xc3\xb6\xc3\x9f" "e \xc3\x86r\xc3\xb8";
        char text[128]; SQLLEN ind = SQL_NTS, got = 0;
        SQLWCHAR wide[128]; SQLLEN wgot = 0;

        CHECK(SQL_HANDLE_STMT, stmt, SQLPrepare(stmt,
            (SQLCHAR *)"INSERT INTO odbc_conformance VALUES(9100,?);", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindParameter(stmt, 1, SQL_PARAM_INPUT,
            SQL_C_CHAR, SQL_VARCHAR, 64, 0, (SQLPOINTER)sample, (SQLLEN)sizeof(sample), &ind));
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecute(stmt));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_RESET_PARAMS));

        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT name FROM odbc_conformance WHERE id=9100;", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, text, sizeof(text), &got));
        VERIFY(!strcmp(text, sample));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        /* The wide path always carries the full Unicode value. */
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT name FROM odbc_conformance WHERE id=9100;", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_WCHAR, wide, sizeof(wide), &wgot));
        /* G r o-umlaut sharp-s e space AE r o-slash = 9 characters. */
        VERIFY(wgot == (SQLLEN)(9 * sizeof(SQLWCHAR)));
        VERIFY(wide[2] == 0x00F6 && wide[3] == 0x00DF);
        VERIFY(wide[6] == 0x00C6 && wide[8] == 0x00F8);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"DELETE FROM odbc_conformance WHERE id=9100;", SQL_NTS));
    }

    /* ---- catalog handling in the metadata calls ----------------------- */
    {
        char text[256]; SQLLEN got = 0; int rows;

        /* catalog "%" with empty schema and table enumerates the catalogs. */
        CHECK(SQL_HANDLE_STMT, stmt, SQLTables(stmt, (SQLCHAR *)"%", SQL_NTS,
            (SQLCHAR *)"", 0, (SQLCHAR *)"", 0, NULL, 0));
        rows = 0;
        while (SQL_SUCCEEDED(SQLFetch(stmt))) {
            CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, text, sizeof(text), &got));
            if (!strcmp(text, "odbc_conformance.db")) rows++;
        }
        VERIFY(rows == 1);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        /* A normal call reports the current database as TABLE_CAT. */
        CHECK(SQL_HANDLE_STMT, stmt, SQLTables(stmt, NULL, 0, NULL, 0,
            (SQLCHAR *)"odbc_conformance", SQL_NTS, (SQLCHAR *)"TABLE", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, text, sizeof(text), &got));
        VERIFY(!strcmp(text, "odbc_conformance.db"));
        VERIFY(SQLFetch(stmt) == SQL_NO_DATA);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        /* A different catalog cannot be answered, so it must come back empty
           rather than reporting this database's tables under that name. */
        CHECK(SQL_HANDLE_STMT, stmt, SQLTables(stmt, (SQLCHAR *)"other.db", SQL_NTS,
            NULL, 0, (SQLCHAR *)"odbc_conformance", SQL_NTS, NULL, 0));
        VERIFY(SQLFetch(stmt) == SQL_NO_DATA);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        /* The table-type enumeration special case. */
        CHECK(SQL_HANDLE_STMT, stmt, SQLTables(stmt, (SQLCHAR *)"", 0, (SQLCHAR *)"", 0,
            (SQLCHAR *)"", 0, (SQLCHAR *)"%", SQL_NTS));
        rows = 0;
        while (SQL_SUCCEEDED(SQLFetch(stmt))) rows++;
        VERIFY(rows == 2);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---- ODBC escape sequences ---------------------------------------- */
    {
        char text[128]; SQLLEN got = 0; SQLINTEGER nlen = 0;

        /* {fn ...} for every function SQL_STRING_FUNCTIONS advertises. */
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT {fn UCASE('abc')};", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, text, sizeof(text), &got));
        VERIFY(!strcmp(text, "ABC"));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT {fn SUBSTRING({fn LCASE('ABCDEF')},2,3)};", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, text, sizeof(text), &got));
        VERIFY(!strcmp(text, "bcd"));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        /* Timestamp literal escapes, as emitted by Access and Excel. */
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT {ts '2020-01-02 03:04:05'};", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, text, sizeof(text), &got));
        VERIFY(!strcmp(text, "2020-01-02 03:04:05"));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        /* {escape 'c'} must become a real ESCAPE clause. */
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT count(*) FROM odbc_conformance "
                       "WHERE name LIKE 'row!-01' {escape '!'};", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, text, sizeof(text), &got));
        VERIFY(!strcmp(text, "1"));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        /* Braces inside string literals must survive untouched. */
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT '{fn UCASE(x)}';", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECK(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, text, sizeof(text), &got));
        VERIFY(!strcmp(text, "{fn UCASE(x)}"));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        /* SQLNativeSql reports the translated text. */
        CHECK(SQL_HANDLE_DBC, dbc, SQLNativeSql(dbc,
            (SQLCHAR *)"SELECT {fn UCASE(a)} FROM t", SQL_NTS,
            (SQLCHAR *)text, (SQLINTEGER)sizeof(text), &nlen));
        VERIFY(!strcmp(text, "SELECT upper(a) FROM t"));
    }

    /* ---- SQLCancel on an idle statement must not kill the connection -- */
    {
        SQLULEN dead = SQL_CD_TRUE;
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id FROM odbc_conformance;", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLCancel(stmt));
        CHECK(SQL_HANDLE_DBC, dbc, SQLGetConnectAttr(dbc, SQL_ATTR_CONNECTION_DEAD,
            &dead, 0, NULL));
        VERIFY(dead == SQL_CD_FALSE);
        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT 1;", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---- concurrent use of one connection ---------------------------- */
    {
        pthread_t threads[4];
        struct worker_arg args[4];
        int t;
        for (t = 0; t < 4; t++) {
            args[t].dbc = dbc; args[t].iterations = 25; args[t].errors = 0;
            VERIFY(pthread_create(&threads[t], NULL, worker, &args[t]) == 0);
        }
        for (t = 0; t < 4; t++) pthread_join(threads[t], NULL);
        for (t = 0; t < 4; t++) {
            if (args[t].errors) fprintf(stderr, "FAIL: worker %d hit %d errors\n", t, args[t].errors);
            VERIFY(args[t].errors == 0);
        }
    }

    /* ---- disconnect frees statements and rolls back ------------------- */
    {
        SQLHDBC other = SQL_NULL_HDBC; SQLHSTMT s1 = SQL_NULL_HSTMT, s2 = SQL_NULL_HSTMT;
        SQLLEN count = 0;

        CHECK(SQL_HANDLE_DBC, dbc, connect_new(env, &other));
        CHECK(SQL_HANDLE_DBC, other, SQLSetConnectAttr(other, SQL_ATTR_CURRENT_CATALOG,
            (SQLPOINTER)"odbc_conformance.db", SQL_NTS));
        CHECK(SQL_HANDLE_DBC, other, SQLAllocHandle(SQL_HANDLE_STMT, other, &s1));
        CHECK(SQL_HANDLE_DBC, other, SQLAllocHandle(SQL_HANDLE_STMT, other, &s2));
        CHECK(SQL_HANDLE_DBC, other, SQLSetConnectAttr(other, SQL_ATTR_AUTOCOMMIT,
            (SQLPOINTER)(uintptr_t)SQL_AUTOCOMMIT_OFF, 0));
        CHECK(SQL_HANDLE_STMT, s1, SQLExecDirect(s1,
            (SQLCHAR *)"INSERT INTO odbc_conformance VALUES(9001,'uncommitted');", SQL_NTS));
        /* Leaving both statements allocated on purpose. */
        CHECK(SQL_HANDLE_DBC, other, SQLDisconnect(other));
        CHECK(SQL_HANDLE_DBC, other, SQLFreeHandle(SQL_HANDLE_DBC, other));

        CHECK(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT count(*) FROM odbc_conformance WHERE id=9001;", SQL_NTS));
        CHECK(SQL_HANDLE_STMT, stmt, SQLBindCol(stmt, 1, SQL_C_SBIGINT, &count, sizeof(count), NULL));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        VERIFY(count == 0);
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_UNBIND));
        CHECK(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    printf("CubeSQL ODBC conformance: PASS\n");

cleanup:
    if (stmt) { SQLFreeStmt(stmt, SQL_CLOSE); SQLFreeHandle(SQL_HANDLE_STMT, stmt); }
    if (dbc) { SQLDisconnect(dbc); SQLFreeHandle(SQL_HANDLE_DBC, dbc); }
    if (env) SQLFreeHandle(SQL_HANDLE_ENV, env);
    return failures ? 1 : 0;
}
