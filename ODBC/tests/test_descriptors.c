/*
 * I descrittori impliciti.
 *
 * Sono il prerequisito per dichiarare ODBC 3.x, e in questo driver non sono un
 * archivio separato: sono quattro viste sullo stato di binding che lo statement
 * gia' tiene. Il valore di questa suite sta soprattutto li' - verificare che
 * SQLBindCol e SQLSetDescField vedano gli stessi campi, perche' il modo classico
 * in cui il supporto ai descrittori marcisce e' tenere due copie che divergono.
 *
 * Non serve il Driver Manager: il driver e' collegato dentro l'eseguibile e
 * chiamato direttamente.
 */
#include "test_common.h"

int main(void) {
    SQLHENV env; SQLHDBC dbc; SQLHSTMT stmt;
    SQLHDESC ard = SQL_NULL_HDESC, apd = SQL_NULL_HDESC;
    SQLHDESC ird = SQL_NULL_HDESC, ipd = SQL_NULL_HDESC;
    SQLRETURN rc;

    if (!cs_test_open(&env, &dbc, &stmt, "odbc_desc.db", "")) return 2;

    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS t_desc;", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"CREATE TABLE t_desc(id INTEGER, nome TEXT);", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"INSERT INTO t_desc VALUES(7,'sette');", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

    /* ---------------------------------------------------------------- *
     * 1. Lo statement possiede quattro descrittori, tutti distinti e tutti
     *    ad allocazione automatica.
     * ---------------------------------------------------------------- */
    {
        SQLSMALLINT alloc = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_APP_ROW_DESC, &ard, 0, NULL));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_APP_PARAM_DESC, &apd, 0, NULL));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_IMP_ROW_DESC, &ird, 0, NULL));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_IMP_PARAM_DESC, &ipd, 0, NULL));
        VERIFY(ard && apd && ird && ipd);
        VERIFY(ard != apd && ard != ird && ard != ipd);
        VERIFY(apd != ird && apd != ipd && ird != ipd);

        CHECKED(SQL_HANDLE_DESC, ard, SQLGetDescField(ard, 0, SQL_DESC_ALLOC_TYPE, &alloc, 0, NULL));
        VERIFY(alloc == SQL_DESC_ALLOC_AUTO);

        /* Liberarli e' un errore, non un no-op: appartengono allo statement. */
        rc = SQLFreeHandle(SQL_HANDLE_DESC, ard);
        VERIFY(rc == SQL_ERROR);
    }

    /* ---------------------------------------------------------------- *
     * 2. SQLBindCol e il descrittore di riga applicativo sono la stessa cosa
     *    vista da due parti. E' il punto centrale del progetto.
     * ---------------------------------------------------------------- */
    {
        SQLINTEGER valore = 0;
        SQLLEN indicatore = 0;
        SQLPOINTER letto = NULL;
        SQLSMALLINT tipo = 0;
        SQLLEN *ind_letto = NULL;
        SQLSMALLINT conteggio = 0;

        CHECKED(SQL_HANDLE_STMT, stmt, SQLBindCol(stmt, 1, SQL_C_SLONG, &valore,
                                                  sizeof(valore), &indicatore));
        CHECKED(SQL_HANDLE_DESC, ard, SQLGetDescField(ard, 1, SQL_DESC_DATA_PTR, &letto, 0, NULL));
        VERIFY(letto == (SQLPOINTER)&valore);
        CHECKED(SQL_HANDLE_DESC, ard, SQLGetDescField(ard, 1, SQL_DESC_TYPE, &tipo, 0, NULL));
        VERIFY(tipo == SQL_C_SLONG);
        CHECKED(SQL_HANDLE_DESC, ard, SQLGetDescField(ard, 1, SQL_DESC_INDICATOR_PTR,
                                                      &ind_letto, 0, NULL));
        VERIFY(ind_letto == &indicatore);
        CHECKED(SQL_HANDLE_DESC, ard, SQLGetDescField(ard, 0, SQL_DESC_COUNT, &conteggio, 0, NULL));
        VERIFY(conteggio >= 1);

        /* E nell'altra direzione: quello che si scrive nel descrittore deve
           essere il binding con cui il driver poi legge davvero. */
        {
            SQLINTEGER altro = 0;
            CHECKED(SQL_HANDLE_DESC, ard, SQLSetDescField(ard, 1, SQL_DESC_DATA_PTR, &altro, 0));
            CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
                (SQLCHAR *)"SELECT id FROM t_desc;", SQL_NTS));
            CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
            VERIFY(altro == 7);
            VERIFY(valore == 0);   /* il vecchio buffer non e' piu' quello attivo */
            CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        }
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_UNBIND));
    }

    /* ---------------------------------------------------------------- *
     * 3. Il descrittore di riga di implementazione descrive il result set, e
     *    deve dire le stesse cose di SQLDescribeCol.
     * ---------------------------------------------------------------- */
    {
        SQLCHAR nome_col[128] = "";
        SQLSMALLINT tipo_desc = 0, tipo_dc = 0, conteggio = 0, nullable = 0;
        SQLULEN dimensione = 0;
        SQLSMALLINT decimali = 0, nul_dc = 0;
        SQLCHAR nome_dc[128] = "";

        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id, nome FROM t_desc;", SQL_NTS));

        CHECKED(SQL_HANDLE_DESC, ird, SQLGetDescField(ird, 0, SQL_DESC_COUNT, &conteggio, 0, NULL));
        VERIFY(conteggio == 2);

        CHECKED(SQL_HANDLE_DESC, ird, SQLGetDescField(ird, 2, SQL_DESC_NAME, nome_col,
                                                      sizeof(nome_col), NULL));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLDescribeCol(stmt, 2, nome_dc, sizeof(nome_dc), NULL,
                                                      &tipo_dc, &dimensione, &decimali, &nul_dc));
        VERIFY(strcmp((char *)nome_col, (char *)nome_dc) == 0);

        CHECKED(SQL_HANDLE_DESC, ird, SQLGetDescField(ird, 2, SQL_DESC_TYPE, &tipo_desc, 0, NULL));
        VERIFY(tipo_desc == tipo_dc);
        CHECKED(SQL_HANDLE_DESC, ird, SQLGetDescField(ird, 2, SQL_DESC_NULLABLE, &nullable, 0, NULL));
        VERIFY(nullable == nul_dc);

        /* SQLGetDescRec deve raccontare la stessa riga in un colpo solo. */
        {
            SQLCHAR nome_rec[128] = "";
            SQLSMALLINT len_rec = 0, tipo_rec = 0, sub = 0, prec = 0, scala = 0, nul_rec = 0;
            SQLLEN lunghezza = 0;
            CHECKED(SQL_HANDLE_DESC, ird, SQLGetDescRec(ird, 2, nome_rec, sizeof(nome_rec), &len_rec,
                                                        &tipo_rec, &sub, &lunghezza, &prec, &scala,
                                                        &nul_rec));
            VERIFY(strcmp((char *)nome_rec, (char *)nome_dc) == 0);
            VERIFY(tipo_rec == tipo_dc);
            VERIFY(nul_rec == nul_dc);
            /* oltre l'ultimo record: SQL_NO_DATA, non un errore */
            rc = SQLGetDescRec(ird, (SQLSMALLINT)(conteggio + 1), nome_rec, sizeof(nome_rec),
                               &len_rec, &tipo_rec, &sub, &lunghezza, &prec, &scala, &nul_rec);
            VERIFY(rc == SQL_NO_DATA);
        }

        /* E' di sola lettura. */
        rc = SQLSetDescField(ird, 1, SQL_DESC_TYPE, (SQLPOINTER)(SQLLEN)SQL_C_CHAR, 0);
        VERIFY(rc == SQL_ERROR);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 4. I campi di intestazione stanno sullo stesso stato degli attributi di
     *    statement corrispondenti.
     * ---------------------------------------------------------------- */
    {
        SQLULEN dimensione = 0;
        SQLULEN righe = 0;
        SQLULEN *puntatore = NULL;

        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE,
                                                      (SQLPOINTER)(SQLULEN)4, 0));
        CHECKED(SQL_HANDLE_DESC, ard, SQLGetDescField(ard, 0, SQL_DESC_ARRAY_SIZE,
                                                      &dimensione, 0, NULL));
        VERIFY(dimensione == 4);

        CHECKED(SQL_HANDLE_DESC, ard, SQLSetDescField(ard, 0, SQL_DESC_ARRAY_SIZE,
                                                      (SQLPOINTER)(SQLULEN)2, 0));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE,
                                                      &dimensione, 0, NULL));
        VERIFY(dimensione == 2);

        /* zero non e' una dimensione valida */
        rc = SQLSetDescField(ard, 0, SQL_DESC_ARRAY_SIZE, (SQLPOINTER)(SQLULEN)0, 0);
        VERIFY(rc == SQL_ERROR);

        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROWS_FETCHED_PTR, &righe, 0));
        CHECKED(SQL_HANDLE_DESC, ird, SQLGetDescField(ird, 0, SQL_DESC_ROWS_PROCESSED_PTR,
                                                      &puntatore, 0, NULL));
        VERIFY(puntatore == &righe);

        /* ARRAY_SIZE non esiste sui descrittori di implementazione */
        rc = SQLGetDescField(ird, 0, SQL_DESC_ARRAY_SIZE, &dimensione, 0, NULL);
        VERIFY(rc == SQL_ERROR);

        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROW_ARRAY_SIZE,
                                                      (SQLPOINTER)(SQLULEN)1, 0));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLSetStmtAttr(stmt, SQL_ATTR_ROWS_FETCHED_PTR, NULL, 0));
    }

    /* ---------------------------------------------------------------- *
     * 5. I due descrittori di parametro, dai due lati dello stesso binding.
     * ---------------------------------------------------------------- */
    {
        SQLINTEGER parametro = 7;
        SQLLEN ind = 0;
        SQLSMALLINT tipo_c = 0, tipo_sql = 0, io = 0, conteggio = 0;
        SQLPOINTER dato = NULL;

        CHECKED(SQL_HANDLE_STMT, stmt, SQLPrepare(stmt,
            (SQLCHAR *)"SELECT nome FROM t_desc WHERE id = ?;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_SLONG,
            SQL_INTEGER, 0, 0, &parametro, 0, &ind));

        CHECKED(SQL_HANDLE_DESC, apd, SQLGetDescField(apd, 0, SQL_DESC_COUNT, &conteggio, 0, NULL));
        VERIFY(conteggio == 1);
        CHECKED(SQL_HANDLE_DESC, apd, SQLGetDescField(apd, 1, SQL_DESC_TYPE, &tipo_c, 0, NULL));
        VERIFY(tipo_c == SQL_C_SLONG);
        CHECKED(SQL_HANDLE_DESC, apd, SQLGetDescField(apd, 1, SQL_DESC_DATA_PTR, &dato, 0, NULL));
        VERIFY(dato == (SQLPOINTER)&parametro);

        CHECKED(SQL_HANDLE_DESC, ipd, SQLGetDescField(ipd, 1, SQL_DESC_TYPE, &tipo_sql, 0, NULL));
        VERIFY(tipo_sql == SQL_INTEGER);
        CHECKED(SQL_HANDLE_DESC, ipd, SQLGetDescField(ipd, 1, SQL_DESC_PARAMETER_TYPE, &io, 0, NULL));
        VERIFY(io == SQL_PARAM_INPUT);

        /* il binding scritto dal descrittore deve valere per l'esecuzione */
        {
            SQLCHAR nome[64] = "";
            SQLLEN ln = 0;
            SQLINTEGER altro = 7;
            CHECKED(SQL_HANDLE_DESC, apd, SQLSetDescField(apd, 1, SQL_DESC_DATA_PTR, &altro, 0));
            CHECKED(SQL_HANDLE_STMT, stmt, SQLExecute(stmt));
            CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
            CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, nome, sizeof(nome), &ln));
            VERIFY(strcmp((char *)nome, "sette") == 0);
            CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
        }
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_RESET_PARAMS));
    }

    /* ---------------------------------------------------------------- *
     * 6. Errori: record fuori intervallo, campo sconosciuto, copia non
     *    implementata. Devono essere errori dichiarati, non silenzi.
     * ---------------------------------------------------------------- */
    {
        SQLSMALLINT v = 0;
        rc = SQLGetDescField(ard, 0, 9999, &v, 0, NULL);
        VERIFY(rc == SQL_ERROR);
        rc = SQLGetDescField(ard, -1, SQL_DESC_TYPE, &v, 0, NULL);
        VERIFY(rc == SQL_ERROR);
        rc = SQLCopyDesc(ard, apd);
        VERIFY(rc == SQL_ERROR);
        rc = SQLGetDescField(SQL_NULL_HDESC, 1, SQL_DESC_TYPE, &v, 0, NULL);
        VERIFY(rc == SQL_INVALID_HANDLE);
    }

    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS t_desc;", SQL_NTS));
    cs_test_close(env, dbc, stmt);
    return cs_test_report("descriptors");
}
