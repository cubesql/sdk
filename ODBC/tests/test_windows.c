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
    /* Conformita' dichiarata dal driver: decide quali controlli sono applicabili. */
    int driver_is_3x = 0;
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
        /*
         * ODBC requires SQL_DRIVER_VER in the form ##.##.####, so any major
         * version below 10 legitimately starts with '0' - 1.1.0 is "01.01.0000".
         * The old test rejected the leading '0' and therefore failed every
         * correctly formatted version. Reject only an empty or all-zero string.
         */
        if (!driver_ver[0] || strcmp((const char *)driver_ver, "00.00.0000") == 0) {
            fprintf(stderr, "SQL_DRIVER_VER is missing or zero.\n");
            goto fail;
        }
    }
    {
        /*
         * Gli InfoType che un consumer ODBC chiede di continuo. La prima
         * release ne falliva quasi tutti con HY096, ed e' cio' che faceva
         * rinunciare Excel e ADO durante la connessione.
         *
         * L'elenco e' diviso in due, e la ragione conta.
         *
         * Il primo gruppo esiste da ODBC 1.0/2.0: un driver deve rispondere,
         * qualunque conformita' dichiari.
         *
         * Il secondo esiste solo da ODBC 3.0 - in sqlext.h sta dentro
         * #if (ODBCVER >= 0x0300). Se il driver si dichiara ODBC 2.x il Driver
         * Manager li respinge da solo, con "[Microsoft][ODBC Driver Manager]
         * Information type out of range", senza nemmeno interpellarlo. Preten-
         * derli da un driver 2.x significherebbe chiedere qualcosa che per
         * costruzione non puo' accadere, e questo controllo falliva sempre pur
         * essendo il driver a implementarli tutti.
         *
         * Cosi' il test misura la conformita' dichiarata: se un giorno il
         * driver passera' a 3.x, il secondo gruppo diventera' obbligatorio da
         * solo, senza che nessuno debba ricordarsi di riattivarlo.
         */
        static const SQLUSMALLINT infos_2x[] = {
            SQL_STRING_FUNCTIONS, SQL_NUMERIC_FUNCTIONS, SQL_TIMEDATE_FUNCTIONS,
            SQL_SYSTEM_FUNCTIONS, SQL_CONVERT_FUNCTIONS, SQL_KEYWORDS,
            SQL_FILE_USAGE, SQL_SUBQUERIES, SQL_UNION, SQL_GROUP_BY,
            SQL_CORRELATION_NAME, SQL_NON_NULLABLE_COLUMNS, SQL_POS_OPERATIONS,
            SQL_BOOKMARK_PERSISTENCE, SQL_SCROLL_CONCURRENCY, SQL_CATALOG_USAGE
        };
        static const SQLUSMALLINT infos_3x[] = {
            SQL_STATIC_CURSOR_ATTRIBUTES1, SQL_STATIC_CURSOR_ATTRIBUTES2,
            SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES1, SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES2,
            SQL_DYNAMIC_CURSOR_ATTRIBUTES1, SQL_KEYSET_CURSOR_ATTRIBUTES1,
            SQL_ACTIVE_ENVIRONMENTS, SQL_CREATE_TABLE, SQL_DROP_TABLE,
            SQL_INDEX_KEYWORDS, SQL_AGGREGATE_FUNCTIONS,
            SQL_ODBC_INTERFACE_CONFORMANCE, SQL_INSERT_STATEMENT,
            /*
             * SQL_OJ_CAPABILITIES nasce con ODBC 2.01 e in sqlext.h non ha
             * guardia, ma il Driver Manager di Windows lo inoltra solo a un
             * driver 3.x: verificato dichiarando 02.00 e 02.01, respinto in
             * entrambi i casi benche' il driver lo implementi.
             */
            SQL_OJ_CAPABILITIES
        };
        char driver_odbc_ver[16] = "";
        char buffer[4096]; SQLSMALLINT len = 0; size_t i; int bad = 0;

        ODBC(SQLGetInfoA(dbc, SQL_DRIVER_ODBC_VER, driver_odbc_ver,
                         sizeof(driver_odbc_ver), &len), SQL_HANDLE_DBC, dbc);
        driver_is_3x = (driver_odbc_ver[0] >= '0' && atoi(driver_odbc_ver) >= 3);
        fprintf(stderr, "SQL_DRIVER_ODBC_VER=%s -> InfoType ODBC 3.x %s\n",
                driver_odbc_ver, driver_is_3x ? "richiesti" : "non applicabili");

        for (i = 0; i < sizeof(infos_2x) / sizeof(infos_2x[0]); i++) {
            SQLRETURN rc = SQLGetInfoA(dbc, infos_2x[i], buffer, sizeof(buffer), &len);
            if (!SQL_SUCCEEDED(rc)) {
                fprintf(stderr, "SQLGetInfo(%u) -> %d\n", (unsigned)infos_2x[i], rc);
                bad++;
            }
        }
        for (i = 0; i < sizeof(infos_3x) / sizeof(infos_3x[0]); i++) {
            SQLRETURN rc = SQLGetInfoA(dbc, infos_3x[i], buffer, sizeof(buffer), &len);
            if (!SQL_SUCCEEDED(rc) && driver_is_3x) {
                fprintf(stderr, "SQLGetInfo(%u) -> %d\n", (unsigned)infos_3x[i], rc);
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
        /*
         * Gli attributi che i consumer impostano sempre non devono essere
         * fatali. SQL_ATTR_NOSCAN esiste da ODBC 1.0 e va accettato comunque.
         *
         * SQL_ATTR_METADATA_ID invece nasce con ODBC 3.0: verso un driver 2.x
         * il Driver Manager lo respinge da solo con HY092 "Option type out of
         * range", senza interpellarlo. Come per gli InfoType 3.x, e' richiesto
         * solo quando il driver dichiara 3.x, altrimenti si pretenderebbe una
         * cosa che il Driver Manager rende impossibile.
         */
        ODBC(SQLSetStmtAttr(stmt, SQL_ATTR_NOSCAN, (SQLPOINTER)(SQLULEN)SQL_NOSCAN_OFF, 0),
             SQL_HANDLE_STMT, stmt);
        if (driver_is_3x) {
            ODBC(SQLSetStmtAttr(stmt, SQL_ATTR_METADATA_ID, (SQLPOINTER)(SQLULEN)SQL_FALSE, 0),
                 SQL_HANDLE_STMT, stmt);
            ODBC(SQLSetConnectAttr(dbc, SQL_ATTR_METADATA_ID, (SQLPOINTER)(SQLULEN)SQL_FALSE, 0),
                 SQL_HANDLE_DBC, dbc);
        }
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
