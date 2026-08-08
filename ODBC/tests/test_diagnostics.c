/*
 * Diagnostiche e funzioni di catalogo rimaste scoperte.
 *
 * Il pezzo piu' importante e' SQLError: e' l'interfaccia ODBC 2.x e va
 * percorsa un record per chiamata fino a SQL_NO_DATA. Restituiva sempre il
 * record 1, quindi chi la chiama in ciclo - Driver Manager compreso - non
 * usciva mai. Nessun test la chiamava.
 */
#include "test_common.h"

int main(void) {
    SQLHENV env; SQLHDBC dbc; SQLHSTMT stmt;

    if (!cs_test_open(&env, &dbc, &stmt, "odbc_diag.db", "")) return 2;

    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS t_diag;", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"CREATE TABLE t_diag(id INTEGER, nome TEXT);", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"INSERT INTO t_diag VALUES(1,'uno');", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

    /* ---------------------------------------------------------------- *
     * 1. Dopo un errore ci deve essere una diagnostica leggibile.
     * ---------------------------------------------------------------- */
    {
        SQLCHAR state[6] = "", msg[512] = "";
        SQLINTEGER native = 0; SQLSMALLINT len = 0;
        SQLINTEGER number = 0;
        SQLRETURN rc;

        rc = SQLExecDirect(stmt, (SQLCHAR *)"SELECT * FROM tabella_inesistente;", SQL_NTS);
        VERIFY(rc == SQL_ERROR);

        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLGetDiagField(SQL_HANDLE_STMT, stmt, 0, SQL_DIAG_NUMBER, &number, 0, NULL));
        VERIFY(number >= 1);

        rc = SQLGetDiagRec(SQL_HANDLE_STMT, stmt, 1, state, &native, msg, sizeof(msg), &len);
        VERIFY(rc == SQL_SUCCESS);
        VERIFY(strlen((char *)state) == 5);
        VERIFY(len > 0);
        VERIFY(strlen((char *)msg) == (size_t)len);

        /* oltre l'ultimo record deve arrivare SQL_NO_DATA, non un errore */
        rc = SQLGetDiagRec(SQL_HANDLE_STMT, stmt, (SQLSMALLINT)(number + 1),
                           state, &native, msg, sizeof(msg), &len);
        VERIFY(rc == SQL_NO_DATA);

        /* stesso contenuto dalla via Unicode */
        {
            SQLWCHAR wstate[6]; SQLWCHAR wmsg[512];
            SQLSMALLINT wlen = 0;
            memset(wstate, 0, sizeof(wstate)); memset(wmsg, 0, sizeof(wmsg));
            rc = SQLGetDiagRecW(SQL_HANDLE_STMT, stmt, 1, wstate, &native, wmsg,
                                512, &wlen);
            VERIFY(rc == SQL_SUCCESS);
            VERIFY(wlen > 0);
        }

        /* i singoli campi diagnostici */
        {
            SQLCHAR field[256] = "";
            SQLSMALLINT flen = 0;
            CHECKED(SQL_HANDLE_STMT, stmt, SQLGetDiagField(SQL_HANDLE_STMT, stmt, 1,
                SQL_DIAG_SQLSTATE, field, sizeof(field), &flen));
            VERIFY(strlen((char *)field) == 5);
            field[0] = '\0';
            CHECKED(SQL_HANDLE_STMT, stmt, SQLGetDiagField(SQL_HANDLE_STMT, stmt, 1,
                SQL_DIAG_MESSAGE_TEXT, field, sizeof(field), &flen));
            VERIFY(strlen((char *)field) > 0);
        }
    }

    /* ---------------------------------------------------------------- *
     * 2. SQLError deve avanzare di un record per chiamata e finire con
     *    SQL_NO_DATA. Se restituisse sempre lo stesso record, il ciclo qui
     *    sotto non terminerebbe: e' esattamente il difetto che bloccava la
     *    macchina, quindi il test si autolimita per non ripeterlo.
     * ---------------------------------------------------------------- */
    {
        SQLCHAR state[6] = "", msg[512] = "";
        SQLINTEGER native = 0; SQLSMALLINT len = 0;
        SQLRETURN rc;
        int giri = 0, records = 0;

        rc = SQLExecDirect(stmt, (SQLCHAR *)"SELECT * FROM ancora_inesistente;", SQL_NTS);
        VERIFY(rc == SQL_ERROR);

        for (giri = 0; giri < 64; giri++) {
            rc = SQLError(SQL_NULL_HENV, SQL_NULL_HDBC, stmt, state, &native,
                          msg, sizeof(msg), &len);
            if (rc == SQL_NO_DATA) break;
            if (!SQL_SUCCEEDED(rc)) { fprintf(stderr, "FAIL: SQLError rc=%d\n", rc); cs_failures++; break; }
            records++;
        }
        if (giri >= 64) {
            fprintf(stderr, "FAIL: SQLError non ha mai restituito SQL_NO_DATA "
                            "(ciclo infinito per chi la usa)\n");
            cs_failures++;
        }
        VERIFY(records >= 1);
        VERIFY(records < 64);

        /* dopo una chiamata riuscita il contatore riparte da capo */
        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id FROM t_diag;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        rc = SQLError(SQL_NULL_HENV, SQL_NULL_HDBC, stmt, state, &native,
                      msg, sizeof(msg), &len);
        VERIFY(rc == SQL_NO_DATA);
    }

    /* ---------------------------------------------------------------- *
     * 3. Funzioni di catalogo che nessun test toccava. CubeSQL non ha
     *    procedure ne' privilegi per tabella: devono rispondere con un
     *    result set vuoto, non con un errore.
     * ---------------------------------------------------------------- */
    {
        SQLSMALLINT cols = 0;
        int rows;

        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLProcedures(stmt, NULL, 0, NULL, 0, NULL, 0));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLNumResultCols(stmt, &cols));
        VERIFY(cols > 0);
        rows = 0; while (SQLFetch(stmt) == SQL_SUCCESS) rows++;
        VERIFY(rows == 0);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLTablePrivileges(stmt, NULL, 0, NULL, 0, (SQLCHAR *)"t_diag", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLNumResultCols(stmt, &cols));
        VERIFY(cols > 0);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLForeignKeys(stmt, NULL, 0, NULL, 0, NULL, 0,
                                 NULL, 0, NULL, 0, (SQLCHAR *)"t_diag", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLNumResultCols(stmt, &cols));
        VERIFY(cols > 0);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLSpecialColumns(stmt, SQL_BEST_ROWID, NULL, 0, NULL, 0,
                              (SQLCHAR *)"t_diag", SQL_NTS, SQL_SCOPE_CURROW, SQL_NULLABLE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLNumResultCols(stmt, &cols));
        VERIFY(cols > 0);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLColumnPrivileges(stmt, NULL, 0, NULL, 0,
                                (SQLCHAR *)"t_diag", SQL_NTS, NULL, 0));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLNumResultCols(stmt, &cols));
        VERIFY(cols > 0);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLProcedureColumns(stmt, NULL, 0, NULL, 0, NULL, 0, NULL, 0));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 4. Nome del cursore, SQLNativeSql, SQLRowCount, SQLMoreResults,
     *    SQLCloseCursor: tutte esportate e mai chiamate.
     * ---------------------------------------------------------------- */
    {
        SQLCHAR name[128] = ""; SQLSMALLINT len = 0;
        SQLCHAR native_sql[256] = ""; SQLINTEGER nlen = 0;
        SQLLEN rowcount = -1;
        SQLRETURN rc;

        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLSetCursorName(stmt, (SQLCHAR *)"cur_diag", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLGetCursorName(stmt, name, sizeof(name), &len));
        VERIFY(!strcmp((char *)name, "cur_diag"));

        /* la traduzione delle escape deve avvenire anche fuori dall'esecuzione */
        CHECKED(SQL_HANDLE_DBC, dbc, SQLNativeSql(dbc,
            (SQLCHAR *)"SELECT {fn UCASE('x')};", SQL_NTS,
            native_sql, sizeof(native_sql), &nlen));
        VERIFY(nlen > 0);
        VERIFY(strstr((char *)native_sql, "{fn") == NULL);

        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"INSERT INTO t_diag VALUES(2,'due');", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLRowCount(stmt, &rowcount));
        VERIFY(rowcount == 1);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id FROM t_diag;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLCloseCursor(stmt));
        /* chiudere due volte deve segnalare 24000, non rompere nulla */
        rc = SQLCloseCursor(stmt);
        VERIFY(rc == SQL_ERROR);

        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id FROM t_diag;", SQL_NTS));
        rc = SQLMoreResults(stmt);
        VERIFY(rc == SQL_NO_DATA);       /* una sola serie di risultati */
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 5. Le funzioni ODBC 2.x di allocazione, mai esercitate.
     * ---------------------------------------------------------------- */
    {
        SQLHENV env2 = SQL_NULL_HENV; SQLHDBC dbc2 = SQL_NULL_HDBC;
        CHECKED(SQL_HANDLE_ENV, env2, SQLAllocEnv(&env2));
        CHECKED(SQL_HANDLE_ENV, env2, SQLAllocConnect(env2, &dbc2));
        CHECKED(SQL_HANDLE_DBC, dbc2, SQLFreeConnect(dbc2));
        CHECKED(SQL_HANDLE_ENV, env2, SQLFreeEnv(env2));
    }

    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS t_diag;", SQL_NTS));
    cs_test_close(env, dbc, stmt);
    return cs_test_report("diagnostics");
}
