/*
 * Varianti Unicode e doppia grafia degli identificatori.
 *
 * Il driver espone 27 funzioni W e 14 funzioni A che nessun test chiamava, e
 * quasi tutte le grafie ODBC 2.x erano scoperte. Tre difetti su dieci di questa
 * verifica stavano proprio li': SQLColAttributeW che non convertiva
 * SQL_COLUMN_NAME, SQL_ROWSET_SIZE rifiutato, SQL_C_TIMESTAMP rifiutato.
 *
 * La regola che questo file mette alla prova e' semplice: ogni cosa deve dare
 * la stessa risposta in ANSI e in Unicode, e con l'identificatore 2.x come con
 * quello 3.x.
 */
#include "test_common.h"

/* Confronta una stringa UTF-16 terminata da zero con una stringa C. */
static int wequal(const SQLWCHAR *w, const char *s) {
    size_t i = 0;
    for (i = 0; s[i]; i++) {
        if (w[i] != (SQLWCHAR)(unsigned char)s[i]) return 0;
    }
    return w[i] == 0;
}

static size_t wlen(const SQLWCHAR *w) {
    size_t n = 0;
    while (w[n]) n++;
    return n;
}

/* Converte una stringa C in UTF-16 per passarla alle funzioni W. */
static void towide(const char *s, SQLWCHAR *out, size_t cap) {
    size_t i = 0;
    for (i = 0; s[i] && i + 1 < cap; i++) out[i] = (SQLWCHAR)(unsigned char)s[i];
    out[i] = 0;
}

int main(void) {
    SQLHENV env; SQLHDBC dbc; SQLHSTMT stmt;
    SQLWCHAR wsql[256];

    if (!cs_test_open(&env, &dbc, &stmt, "odbc_unicode.db", "")) return 2;

    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS t_uni;", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"CREATE TABLE t_uni(id INTEGER, nome TEXT);", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"INSERT INTO t_uni VALUES(1,'uno');", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

    /* ---------------------------------------------------------------- *
     * 1. SQLExecDirectW deve accettare una query in UTF-16.
     * ---------------------------------------------------------------- */
    towide("SELECT id, nome FROM t_uni;", wsql, 256);
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirectW(stmt, wsql, SQL_NTS));

    /* ---------------------------------------------------------------- *
     * 2. I nomi di colonna devono arrivare identici da tutte e quattro le vie:
     *    SQLDescribeCol / SQLDescribeColW, e SQLColAttribute con
     *    SQL_DESC_NAME (3.x) e SQL_COLUMN_NAME (2.x), in ANSI e in Unicode.
     *
     *    E' il controllo che avrebbe intercettato subito i nomi vuoti: le due
     *    entry point tenevano due liste separate dei campi di tipo stringa.
     * ---------------------------------------------------------------- */
    {
        SQLCHAR aname[128] = ""; SQLWCHAR wname[128];
        SQLSMALLINT alen = 0, wlenOut = 0, dt = 0, dd = 0, nu = 0;
        SQLULEN size = 0;
        SQLLEN num = 0;
        SQLUSMALLINT col;
        const char *expected[2] = { "id", "nome" };

        for (col = 1; col <= 2; col++) {
            aname[0] = '\0';
            CHECKED(SQL_HANDLE_STMT, stmt,
                SQLDescribeCol(stmt, col, aname, sizeof(aname), &alen, &dt, &size, &dd, &nu));
            VERIFY(!strcmp((char *)aname, expected[col - 1]));
            VERIFY(alen == (SQLSMALLINT)strlen(expected[col - 1]));

            memset(wname, 0, sizeof(wname));
            CHECKED(SQL_HANDLE_STMT, stmt,
                SQLDescribeColW(stmt, col, wname, 128, &wlenOut, &dt, &size, &dd, &nu));
            VERIFY(wequal(wname, expected[col - 1]));
            VERIFY(wlenOut == (SQLSMALLINT)strlen(expected[col - 1]));

            aname[0] = '\0'; alen = 0;
            CHECKED(SQL_HANDLE_STMT, stmt,
                SQLColAttribute(stmt, col, SQL_DESC_NAME, aname, sizeof(aname), &alen, &num));
            VERIFY(!strcmp((char *)aname, expected[col - 1]));

            aname[0] = '\0'; alen = 0;
            CHECKED(SQL_HANDLE_STMT, stmt,
                SQLColAttribute(stmt, col, SQL_COLUMN_NAME, aname, sizeof(aname), &alen, &num));
            VERIFY(!strcmp((char *)aname, expected[col - 1]));
            VERIFY(alen == (SQLSMALLINT)strlen(expected[col - 1]));

            memset(wname, 0, sizeof(wname)); wlenOut = 0;
            CHECKED(SQL_HANDLE_STMT, stmt,
                SQLColAttributeW(stmt, col, SQL_DESC_NAME, wname, sizeof(wname), &wlenOut, &num));
            VERIFY(wequal(wname, expected[col - 1]));

            /* la via che restava muta: 2.x sull'entry point Unicode */
            memset(wname, 0, sizeof(wname)); wlenOut = 0;
            CHECKED(SQL_HANDLE_STMT, stmt,
                SQLColAttributeW(stmt, col, SQL_COLUMN_NAME, wname, sizeof(wname), &wlenOut, &num));
            VERIFY(wequal(wname, expected[col - 1]));
            VERIFY(wlenOut == (SQLSMALLINT)(strlen(expected[col - 1]) * sizeof(SQLWCHAR)));
            VERIFY(wlen(wname) == strlen(expected[col - 1]));
        }
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 3. Attributi di statement nelle due grafie.
     *    SQL_ROWSET_SIZE (9) e' la forma 2.x di SQL_ATTR_ROW_ARRAY_SIZE (27):
     *    il Driver Manager la sostituisce quando il driver si dichiara 2.0, e
     *    finche' mancava il fetch a blocchi era disattivato.
     * ---------------------------------------------------------------- */
    {
        SQLULEN got = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE,
            (SQLPOINTER)(SQLULEN)4, 0));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE,
            &got, 0, NULL));
        VERIFY(got == 4);

        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ROWSET_SIZE,
            (SQLPOINTER)(SQLULEN)7, 0));
        got = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ROWSET_SIZE, &got, 0, NULL));
        VERIFY(got == 7);
        /* le due grafie devono indicare lo stesso attributo */
        got = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE, &got, 0, NULL));
        VERIFY(got == 7);

        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE,
            (SQLPOINTER)(SQLULEN)1, 0));
    }

    /* ---------------------------------------------------------------- *
     * 4. SQLGetInfo: la variante W deve dare lo stesso testo della ANSI.
     * ---------------------------------------------------------------- */
    {
        SQLCHAR a[128] = ""; SQLWCHAR w[128];
        SQLSMALLINT alen = 0, wlenOut = 0;
        SQLUSMALLINT infos[3];
        int k;
        infos[0] = SQL_DRIVER_NAME; infos[1] = SQL_DBMS_NAME; infos[2] = SQL_DRIVER_VER;

        for (k = 0; k < 3; k++) {
            a[0] = '\0'; memset(w, 0, sizeof(w));
            CHECKED(SQL_HANDLE_DBC, dbc, SQLGetInfo(dbc, infos[k], a, sizeof(a), &alen));
            CHECKED(SQL_HANDLE_DBC, dbc, SQLGetInfoW(dbc, infos[k], w, sizeof(w), &wlenOut));
            VERIFY(wequal(w, (char *)a));
            /* la variante W conta byte, non caratteri */
            VERIFY(wlenOut == (SQLSMALLINT)(strlen((char *)a) * sizeof(SQLWCHAR)));
        }
    }

    /* ---------------------------------------------------------------- *
     * 5. Cataloghi in versione Unicode: SQLTablesW e SQLColumnsW.
     * ---------------------------------------------------------------- */
    {
        SQLWCHAR wtable[64];
        SQLCHAR name[128] = "";
        SQLLEN ind = 0;
        int rows = 0;

        towide("t_uni", wtable, 64);
        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLTablesW(stmt, NULL, 0, NULL, 0, wtable, SQL_NTS, NULL, 0));
        while (SQLFetch(stmt) == SQL_SUCCESS) {
            name[0] = '\0';
            SQLGetData(stmt, 3, SQL_C_CHAR, name, sizeof(name), &ind);
            if (!strcmp((char *)name, "t_uni")) rows++;
        }
        VERIFY(rows == 1);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        rows = 0;
        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLColumnsW(stmt, NULL, 0, NULL, 0, wtable, SQL_NTS, NULL, 0));
        while (SQLFetch(stmt) == SQL_SUCCESS) rows++;
        VERIFY(rows == 2);          /* id, nome */
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 6. SQLPrepareW seguita da SQLExecute, e SQLNumParams.
     * ---------------------------------------------------------------- */
    {
        SQLINTEGER id = 1; SQLLEN ind = 0; SQLSMALLINT nparams = 0;
        SQLCHAR value[64] = "";

        towide("SELECT nome FROM t_uni WHERE id = ?;", wsql, 256);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLPrepareW(stmt, wsql, SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLNumParams(stmt, &nparams));
        VERIFY(nparams == 1);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLBindParameter(stmt, 1, SQL_PARAM_INPUT,
            SQL_C_SLONG, SQL_INTEGER, 0, 0, &id, 0, &ind));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecute(stmt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, value, sizeof(value), &ind));
        VERIFY(!strcmp((char *)value, "uno"));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_RESET_PARAMS));
    }

    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS t_uni;", SQL_NTS));
    cs_test_close(env, dbc, stmt);
    return cs_test_report("unicode");
}
