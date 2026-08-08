/*
 * Alias ODBC 2.x, varianti A/W e funzioni facoltative.
 *
 * Chiude la parte di superficie esportata che nessun test toccava. Molte di
 * queste sono sottili inoltri verso la forma 3.x, ed e' proprio dove si e'
 * annidata piu' volte la stessa classe di errore: una grafia gestita e l'altra
 * no. Le funzioni che il driver non implementa devono comunque rispondere in
 * modo definito, non rompersi: anche quello e' contratto.
 */
#include "test_common.h"
#include <odbcinst.h>

#define ALIAS_DSN "cs_alias_test"

static void towide(const char *s, SQLWCHAR *out, size_t cap) {
    size_t i = 0;
    for (i = 0; s[i] && i + 1 < cap; i++) out[i] = (SQLWCHAR)(unsigned char)s[i];
    out[i] = 0;
}

/* Una funzione non implementata deve rispondere, non far saltare il processo. */
static void expect_defined(SQLRETURN rc, const char *what) {
    if (rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO && rc != SQL_ERROR &&
        rc != SQL_NO_DATA && rc != SQL_INVALID_HANDLE && rc != SQL_NEED_DATA &&
        rc != SQL_STILL_EXECUTING) {
        fprintf(stderr, "FAIL: %s ha restituito %d, che non e' un SQLRETURN definito\n", what, (int)rc);
        cs_failures++;
    }
}

int main(void) {
    SQLHENV env; SQLHDBC dbc; SQLHSTMT stmt;
    SQLWCHAR wbuf[256];
    char conn[512];

    if (!cs_test_open(&env, &dbc, &stmt, "odbc_alias.db", "")) return 2;

    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS t_alias;", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"CREATE TABLE t_alias(id INTEGER, nome TEXT);", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"INSERT INTO t_alias VALUES(1,'uno');", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

    /* ---------------------------------------------------------------- *
     * 1. Alias 2.x per gli attributi: option e attr devono vedere lo stesso
     *    stato. Sono inoltri, ma inoltri che nessuno aveva mai percorso.
     * ---------------------------------------------------------------- */
    {
        SQLULEN v = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetStmtOption(stmt, SQL_MAX_ROWS, 123));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtOption(stmt, SQL_MAX_ROWS, &v));
        VERIFY(v == 123);
        /* la forma 3.x deve leggere lo stesso valore */
        v = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_MAX_ROWS, &v, 0, NULL));
        VERIFY(v == 123);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetStmtOption(stmt, SQL_MAX_ROWS, 0));

        v = 0;
        CHECKED(SQL_HANDLE_DBC, dbc, SQLSetConnectOption(dbc, SQL_ATTR_ACCESS_MODE, SQL_MODE_READ_WRITE));
        CHECKED(SQL_HANDLE_DBC, dbc, SQLGetConnectOption(dbc, SQL_ATTR_ACCESS_MODE, &v));
        VERIFY(v == SQL_MODE_READ_WRITE);
    }

    /* varianti A degli attributi */
    {
        SQLULEN v = 0; SQLINTEGER len = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttrA(stmt, SQL_ATTR_MAX_ROWS, &v, 0, &len));
        CHECKED(SQL_HANDLE_DBC, dbc, SQLGetConnectAttrA(dbc, SQL_ATTR_ACCESS_MODE, &v, 0, &len));
        CHECKED(SQL_HANDLE_DBC, dbc, SQLGetConnectAttrW(dbc, SQL_ATTR_ACCESS_MODE, &v, 0, &len));
        CHECKED(SQL_HANDLE_DBC, dbc, SQLSetConnectAttrA(dbc, SQL_ATTR_ACCESS_MODE,
            (SQLPOINTER)(SQLULEN)SQL_MODE_READ_WRITE, 0));
        CHECKED(SQL_HANDLE_DBC, dbc, SQLSetConnectAttrW(dbc, SQL_ATTR_ACCESS_MODE,
            (SQLPOINTER)(SQLULEN)SQL_MODE_READ_WRITE, 0));
    }

    /* ---------------------------------------------------------------- *
     * 2. Transazioni: SQLTransact e' l'alias 2.x di SQLEndTran.
     * ---------------------------------------------------------------- */
    CHECKED(SQL_HANDLE_DBC, dbc, SQLTransact(SQL_NULL_HENV, dbc, SQL_COMMIT));
    CHECKED(SQL_HANDLE_DBC, dbc, SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT));

    /* ---------------------------------------------------------------- *
     * 3. Allocazione in stile 2.x.
     * ---------------------------------------------------------------- */
    {
        SQLHSTMT s2 = SQL_NULL_HSTMT;
        CHECKED(SQL_HANDLE_DBC, dbc, SQLAllocStmt(dbc, &s2));
        VERIFY(s2 != SQL_NULL_HSTMT);
        if (s2) CHECKED(SQL_HANDLE_STMT, s2, SQLFreeStmt(s2, SQL_DROP));
    }

    /* ---------------------------------------------------------------- *
     * 4. Parametri: SQLBindParam e SQLSetParam sono le forme 2.x di
     *    SQLBindParameter; SQLDescribeParam e SQLParamOptions completano.
     * ---------------------------------------------------------------- */
    {
        SQLINTEGER id = 1; SQLLEN ind = 0; SQLCHAR value[64] = "";
        SQLSMALLINT dtype = 0, ddigits = 0, dnullable = 0;
        SQLULEN dsize = 0;
        SQLRETURN rc;

        CHECKED(SQL_HANDLE_STMT, stmt, SQLPrepare(stmt,
            (SQLCHAR *)"SELECT nome FROM t_alias WHERE id = ?;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLBindParam(stmt, 1, SQL_C_SLONG, SQL_INTEGER,
            0, 0, &id, &ind));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecute(stmt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, value, sizeof(value), &ind));
        VERIFY(!strcmp((char *)value, "uno"));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_RESET_PARAMS));

        CHECKED(SQL_HANDLE_STMT, stmt, SQLPrepare(stmt,
            (SQLCHAR *)"SELECT nome FROM t_alias WHERE id = ?;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetParam(stmt, 1, SQL_C_SLONG, SQL_INTEGER,
            0, 0, &id, &ind));
        /* il driver non descrive i parametri: deve dirlo, non fingere */
        rc = SQLDescribeParam(stmt, 1, &dtype, &dsize, &ddigits, &dnullable);
        expect_defined(rc, "SQLDescribeParam");
        rc = SQLParamOptions(stmt, 1, NULL);
        expect_defined(rc, "SQLParamOptions");
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_RESET_PARAMS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 4-bis. SQLSetScrollOptions: l'ultima funzione ODBC 2.0 che mancava.
     *        Traduce nei tre attributi 3.x, quindi si verifica leggendoli.
     * ---------------------------------------------------------------- */
    {
        SQLULEN v = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetScrollOptions(stmt, SQL_CONCUR_READ_ONLY,
            SQL_SCROLL_STATIC, 4));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_CURSOR_TYPE, &v, 0, NULL));
        VERIFY(v == SQL_CURSOR_STATIC);
        v = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE, &v, 0, NULL));
        VERIFY(v == 4);
        v = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_CONCURRENCY, &v, 0, NULL));
        VERIFY(v == SQL_CONCUR_READ_ONLY);

        /* forward-only e' l'altro caso che i consumer usano davvero */
        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetScrollOptions(stmt, SQL_CONCUR_READ_ONLY,
            SQL_SCROLL_FORWARD_ONLY, 1));
        v = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_CURSOR_TYPE, &v, 0, NULL));
        VERIFY(v == SQL_CURSOR_FORWARD_ONLY);

        /* un rowset non valido va respinto, non accettato in silenzio */
        VERIFY(SQLSetScrollOptions(stmt, SQL_CONCUR_READ_ONLY, SQL_SCROLL_STATIC, 0) == SQL_ERROR);
        /* keyset piu' piccolo del rowset: incoerente, va respinto */
        VERIFY(SQLSetScrollOptions(stmt, SQL_CONCUR_READ_ONLY, 2, 8) == SQL_ERROR);

        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE,
            (SQLPOINTER)(SQLULEN)1, 0));
    }

    /* ---------------------------------------------------------------- *
     * 5. SQLColAttributes, la forma 2.x di SQLColAttribute.
     * ---------------------------------------------------------------- */
    {
        SQLCHAR name[128] = ""; SQLSMALLINT len = 0; SQLLEN num = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id, nome FROM t_alias;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLColAttributes(stmt, 2, SQL_COLUMN_NAME, name, sizeof(name), &len, &num));
        VERIFY(!strcmp((char *)name, "nome"));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 6. Nome del cursore e SQL nativo, nelle varianti Unicode e A.
     * ---------------------------------------------------------------- */
    {
        SQLWCHAR wname[128]; SQLSMALLINT wlen = 0;
        SQLCHAR nativeA[256] = ""; SQLINTEGER nlenA = 0;
        SQLWCHAR nativeW[256]; SQLINTEGER nlenW = 0;

        towide("cur_alias", wbuf, 256);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetCursorNameW(stmt, wbuf, SQL_NTS));
        memset(wname, 0, sizeof(wname));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetCursorNameW(stmt, wname, 128, &wlen));
        VERIFY(wlen > 0);

        CHECKED(SQL_HANDLE_DBC, dbc, SQLNativeSqlA(dbc,
            (SQLCHAR *)"SELECT {fn UCASE('x')};", SQL_NTS, nativeA, sizeof(nativeA), &nlenA));
        VERIFY(nlenA > 0);
        towide("SELECT {fn UCASE('x')};", wbuf, 256);
        CHECKED(SQL_HANDLE_DBC, dbc, SQLNativeSqlW(dbc, wbuf, SQL_NTS, nativeW, 256, &nlenW));
        VERIFY(nlenW > 0);
    }

    /* ---------------------------------------------------------------- *
     * 7. Diagnostiche: le varianti W e A mai chiamate.
     * ---------------------------------------------------------------- */
    {
        SQLCHAR state[6] = "", msg[512] = "";
        SQLWCHAR wstate[6], wmsg[512];
        SQLINTEGER native = 0; SQLSMALLINT len = 0;
        SQLCHAR fieldA[256] = ""; SQLWCHAR fieldW[256];
        SQLRETURN rc;

        rc = SQLExecDirect(stmt, (SQLCHAR *)"SELECT * FROM non_esiste_affatto;", SQL_NTS);
        VERIFY(rc == SQL_ERROR);

        memset(wstate, 0, sizeof(wstate)); memset(wmsg, 0, sizeof(wmsg));
        rc = SQLErrorW(SQL_NULL_HENV, SQL_NULL_HDBC, stmt, wstate, &native, wmsg, 512, &len);
        VERIFY(rc == SQL_SUCCESS);
        /* e la chiamata successiva deve chiudere, non ripetersi all'infinito */
        rc = SQLErrorW(SQL_NULL_HENV, SQL_NULL_HDBC, stmt, wstate, &native, wmsg, 512, &len);
        VERIFY(rc == SQL_NO_DATA);

        rc = SQLExecDirect(stmt, (SQLCHAR *)"SELECT * FROM neanche_questa;", SQL_NTS);
        VERIFY(rc == SQL_ERROR);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetDiagFieldA(SQL_HANDLE_STMT, stmt, 1,
            SQL_DIAG_SQLSTATE, fieldA, sizeof(fieldA), &len));
        VERIFY(strlen((char *)fieldA) == 5);
        memset(fieldW, 0, sizeof(fieldW));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetDiagFieldW(SQL_HANDLE_STMT, stmt, 1,
            SQL_DIAG_SQLSTATE, fieldW, sizeof(fieldW), &len));
        (void)state; (void)msg;
    }

    /* ---------------------------------------------------------------- *
     * 8. Cataloghi: tutte le varianti Unicode rimaste.
     * ---------------------------------------------------------------- */
    {
        SQLWCHAR wtable[64];
        towide("t_alias", wtable, 64);

        CHECKED(SQL_HANDLE_STMT, stmt, SQLPrimaryKeysW(stmt, NULL, 0, NULL, 0, wtable, SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLStatisticsW(stmt, NULL, 0, NULL, 0, wtable, SQL_NTS,
            SQL_INDEX_ALL, SQL_QUICK));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLSpecialColumnsW(stmt, SQL_BEST_ROWID, NULL, 0, NULL, 0,
            wtable, SQL_NTS, SQL_SCOPE_CURROW, SQL_NULLABLE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLForeignKeysW(stmt, NULL, 0, NULL, 0, NULL, 0,
            NULL, 0, NULL, 0, wtable, SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLTablePrivilegesW(stmt, NULL, 0, NULL, 0, wtable, SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLColumnPrivilegesW(stmt, NULL, 0, NULL, 0,
            wtable, SQL_NTS, NULL, 0));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLProceduresW(stmt, NULL, 0, NULL, 0, NULL, 0));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLProcedureColumnsW(stmt, NULL, 0, NULL, 0, NULL, 0, NULL, 0));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetTypeInfoW(stmt, SQL_ALL_TYPES));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 9. Funzioni facoltative che il driver non implementa: devono
     *    rispondere in modo definito e lasciare l'handle utilizzabile.
     * ---------------------------------------------------------------- */
    {
        SQLRETURN rc;
        rc = SQLBulkOperations(stmt, SQL_ADD);            expect_defined(rc, "SQLBulkOperations");
        rc = SQLSetPos(stmt, 1, SQL_POSITION, SQL_LOCK_NO_CHANGE); expect_defined(rc, "SQLSetPos");
        rc = SQLCancelHandle(SQL_HANDLE_STMT, stmt);      expect_defined(rc, "SQLCancelHandle");
        rc = SQLCancel(stmt);                             expect_defined(rc, "SQLCancel");
        /* dopo tutto questo lo statement deve ancora funzionare */
        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id FROM t_alias;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 10. Connessione: SQLConnect e le sue varianti, e SQLDriverConnectW.
     *     Serve un DSN, che si crea con ConfigDSN senza interfaccia.
     * ---------------------------------------------------------------- */
    {
        static const char attrs[] =
            "DSN=" ALIAS_DSN "\0" "SERVER=127.0.0.1\0" "PORT=4430\0"
            "UID=admin\0" "DATABASE=odbc_alias.db\0" "ENCRYPTION=NONE\0";
        static const char rm[] = "DSN=" ALIAS_DSN "\0";
        SQLHDBC d2 = SQL_NULL_HDBC;
        SQLWCHAR wdsn[64], wuser[64], wpass[64];
        SQLRETURN rc;

        ConfigDSN(NULL, ODBC_REMOVE_DSN, "CubeSQL ODBC Driver", rm);
        if (!ConfigDSN(NULL, ODBC_ADD_DSN, "CubeSQL ODBC Driver", attrs)) {
            fprintf(stderr, "FAIL: non sono riuscito a creare il DSN di prova\n");
            cs_failures++;
        } else {
            CHECKED(SQL_HANDLE_DBC, d2, SQLAllocHandle(SQL_HANDLE_DBC, env, &d2));
            CHECKED(SQL_HANDLE_DBC, d2, SQLConnect(d2, (SQLCHAR *)ALIAS_DSN, SQL_NTS,
                (SQLCHAR *)"admin", SQL_NTS, (SQLCHAR *)"admin", SQL_NTS));
            CHECKED(SQL_HANDLE_DBC, d2, SQLDisconnect(d2));

            CHECKED(SQL_HANDLE_DBC, d2, SQLConnectA(d2, (SQLCHAR *)ALIAS_DSN, SQL_NTS,
                (SQLCHAR *)"admin", SQL_NTS, (SQLCHAR *)"admin", SQL_NTS));
            CHECKED(SQL_HANDLE_DBC, d2, SQLDisconnect(d2));

            towide(ALIAS_DSN, wdsn, 64); towide("admin", wuser, 64); towide("admin", wpass, 64);
            CHECKED(SQL_HANDLE_DBC, d2, SQLConnectW(d2, wdsn, SQL_NTS, wuser, SQL_NTS, wpass, SQL_NTS));
            CHECKED(SQL_HANDLE_DBC, d2, SQLDisconnect(d2));

            cs_test_conn_string(conn, sizeof(conn), "");
            towide(conn, wbuf, 256);
            CHECKED(SQL_HANDLE_DBC, d2, SQLDriverConnectW(d2, NULL, wbuf, SQL_NTS,
                NULL, 0, NULL, SQL_DRIVER_NOPROMPT));
            CHECKED(SQL_HANDLE_DBC, d2, SQLDisconnect(d2));

            /* SQLBrowseConnect non e' implementata: deve dirlo con chiarezza */
            rc = SQLBrowseConnect(d2, (SQLCHAR *)conn, SQL_NTS, NULL, 0, NULL);
            expect_defined(rc, "SQLBrowseConnect");
            rc = SQLBrowseConnectW(d2, wbuf, SQL_NTS, NULL, 0, NULL);
            expect_defined(rc, "SQLBrowseConnectW");

            SQLFreeHandle(SQL_HANDLE_DBC, d2);
            ConfigDSN(NULL, ODBC_REMOVE_DSN, "CubeSQL ODBC Driver", rm);
        }
    }

    /* SQLPrepareA, rimasta indietro */
    CHECKED(SQL_HANDLE_STMT, stmt, SQLPrepareA(stmt,
        (SQLCHAR *)"SELECT id FROM t_alias;", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecute(stmt));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS t_alias;", SQL_NTS));
    cs_test_close(env, dbc, stmt);
    return cs_test_report("aliases");
}
