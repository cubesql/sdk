/*
 * Tipi di colonna e conversioni.
 *
 * Copre il territorio in cui si sono annidati piu' difetti e che nessun test
 * toccava: la mappatura dei tipi dichiarati, i tipi C mai esercitati (in
 * particolare data/ora, che esistono in due grafie), i valori NULL, il
 * troncamento e SQLGetData chiamata a blocchi ripetuti.
 */
#include "test_common.h"

static const char *type_name(SQLSMALLINT t) {
    switch (t) {
        case SQL_BIGINT: return "SQL_BIGINT";
        case SQL_INTEGER: return "SQL_INTEGER";
        case SQL_DOUBLE: return "SQL_DOUBLE";
        case SQL_DECIMAL: return "SQL_DECIMAL";
        case SQL_VARCHAR: return "SQL_VARCHAR";
        case SQL_LONGVARBINARY: return "SQL_LONGVARBINARY";
        case SQL_BIT: return "SQL_BIT";
        case SQL_TYPE_DATE: return "SQL_TYPE_DATE";
        case SQL_TYPE_TIME: return "SQL_TYPE_TIME";
        case SQL_TYPE_TIMESTAMP: return "SQL_TYPE_TIMESTAMP";
        default: return "<altro>";
    }
}

/* Verifica che la colonna 'col' sia descritta con il tipo atteso. */
static void expect_type(SQLHSTMT stmt, SQLUSMALLINT col, SQLSMALLINT want, const char *label) {
    SQLCHAR name[128] = "";
    SQLSMALLINT nlen = 0, dt = 0, dd = 0, nullable = 0;
    SQLULEN size = 0;
    SQLLEN num = 0;
    SQLSMALLINT clen = 0;

    CHECKED(SQL_HANDLE_STMT, stmt,
        SQLDescribeCol(stmt, col, name, sizeof(name), &nlen, &dt, &size, &dd, &nullable));
    if (dt != want) {
        fprintf(stderr, "FAIL %s: SQLDescribeCol dice %s, atteso %s\n",
                label, type_name(dt), type_name(want));
        cs_failures++;
    }
    /* il nome deve arrivare, ed essere lungo quanto dichiarato */
    VERIFY(nlen > 0);
    VERIFY((size_t)nlen == strlen((char *)name));

    /* la stessa risposta deve arrivare anche da SQLColAttribute, in entrambe le grafie */
    num = 0;
    CHECKED(SQL_HANDLE_STMT, stmt,
        SQLColAttribute(stmt, col, SQL_DESC_CONCISE_TYPE, NULL, 0, &clen, &num));
    VERIFY((SQLSMALLINT)num == want);
    num = 0;
    CHECKED(SQL_HANDLE_STMT, stmt,
        SQLColAttribute(stmt, col, SQL_COLUMN_TYPE, NULL, 0, &clen, &num));
    VERIFY((SQLSMALLINT)num == want);
}

int main(void) {
    SQLHENV env; SQLHDBC dbc; SQLHSTMT stmt;

    if (!cs_test_open(&env, &dbc, &stmt, "odbc_types.db", "")) return 2;

    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS t_types;", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"CREATE TABLE t_types(id INTEGER, num REAL, txt TEXT, bin BLOB,"
                   " money NUMERIC, ts TIMESTAMP, d DATE, t TIME, vuoto TEXT);", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"INSERT INTO t_types VALUES(42, 3.25, 'abcdefghij', NULL, 9.99,"
                   " '2026-08-08 10:11:12', '2026-08-08', '10:11:12', NULL);", SQL_NTS));
    CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

    /* ---------------------------------------------------------------- *
     * 1. I tipi dichiarati devono arrivare all'applicazione.
     *    CubeSQL riporta come testo il tipo a runtime di una colonna REAL,
     *    quindi senza consultare il catalogo qui si vedrebbe SQL_VARCHAR.
     * ---------------------------------------------------------------- */
    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"SELECT id, num, txt, bin, money, ts, d, t FROM t_types;", SQL_NTS));
    {
        SQLSMALLINT cols = 0;
        CHECKED(SQL_HANDLE_STMT, stmt, SQLNumResultCols(stmt, &cols));
        VERIFY(cols == 8);
    }
    expect_type(stmt, 1, SQL_BIGINT, "id INTEGER");
    expect_type(stmt, 2, SQL_DOUBLE, "num REAL");
    expect_type(stmt, 3, SQL_VARCHAR, "txt TEXT");
    expect_type(stmt, 5, SQL_DECIMAL, "money NUMERIC");
    expect_type(stmt, 6, SQL_TYPE_TIMESTAMP, "ts TIMESTAMP");
    expect_type(stmt, 7, SQL_TYPE_DATE, "d DATE");
    expect_type(stmt, 8, SQL_TYPE_TIME, "t TIME");
    CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

    /* ---------------------------------------------------------------- *
     * 2. Un valore numerico letto con ogni tipo C intero e in virgola mobile.
     * ---------------------------------------------------------------- */
    {
        SQLINTEGER i32 = 0; SQLBIGINT i64 = 0; SQLSMALLINT i16 = 0;
        SQLCHAR i8 = 0; double dbl = 0; float flt = 0; SQLCHAR bit = 0;
        SQLLEN ind = 0;

        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT id FROM t_types;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_SLONG, &i32, sizeof(i32), &ind));
        VERIFY(i32 == 42);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_SBIGINT, &i64, sizeof(i64), &ind));
        VERIFY(i64 == 42);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_SSHORT, &i16, sizeof(i16), &ind));
        VERIFY(i16 == 42);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_STINYINT, &i8, sizeof(i8), &ind));
        VERIFY(i8 == 42);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_DOUBLE, &dbl, sizeof(dbl), &ind));
        VERIFY(dbl == 42.0);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_FLOAT, &flt, sizeof(flt), &ind));
        VERIFY(flt == 42.0f);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT 1 FROM t_types;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_BIT, &bit, sizeof(bit), &ind));
        VERIFY(bit == 1);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));

        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT num FROM t_types;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_DOUBLE, &dbl, sizeof(dbl), &ind));
        VERIFY(dbl > 3.24 && dbl < 3.26);
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 3. Data e ora nelle DUE grafie: 91/92/93 della 3.x e 9/10/11 della 2.x.
     *    Il Driver Manager converte le prime nelle seconde quando il driver si
     *    dichiara ODBC 2.0, quindi vanno accettate entrambe.
     * ---------------------------------------------------------------- */
    {
        SQL_TIMESTAMP_STRUCT ts; SQL_DATE_STRUCT dt; SQL_TIME_STRUCT tm;
        SQLLEN ind = 0;

        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT ts, d, t FROM t_types;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));

        memset(&ts, 0, sizeof(ts));
        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLGetData(stmt, 1, SQL_C_TYPE_TIMESTAMP, &ts, sizeof(ts), &ind));
        VERIFY(ts.year == 2026 && ts.month == 8 && ts.day == 8);
        VERIFY(ts.hour == 10 && ts.minute == 11 && ts.second == 12);

        memset(&ts, 0, sizeof(ts));
        CHECKED(SQL_HANDLE_STMT, stmt,
            SQLGetData(stmt, 1, SQL_C_TIMESTAMP, &ts, sizeof(ts), &ind));
        VERIFY(ts.year == 2026 && ts.month == 8 && ts.day == 8);

        memset(&dt, 0, sizeof(dt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 2, SQL_C_TYPE_DATE, &dt, sizeof(dt), &ind));
        VERIFY(dt.year == 2026 && dt.month == 8 && dt.day == 8);
        memset(&dt, 0, sizeof(dt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 2, SQL_C_DATE, &dt, sizeof(dt), &ind));
        VERIFY(dt.year == 2026 && dt.month == 8 && dt.day == 8);

        memset(&tm, 0, sizeof(tm));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 3, SQL_C_TYPE_TIME, &tm, sizeof(tm), &ind));
        VERIFY(tm.hour == 10 && tm.minute == 11 && tm.second == 12);
        memset(&tm, 0, sizeof(tm));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 3, SQL_C_TIME, &tm, sizeof(tm), &ind));
        VERIFY(tm.hour == 10 && tm.minute == 11 && tm.second == 12);

        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 4. NULL: l'indicatore deve dire SQL_NULL_DATA e il buffer non va toccato.
     * ---------------------------------------------------------------- */
    {
        char buf[64]; SQLLEN ind = 0;
        memset(buf, '#', sizeof(buf));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT vuoto FROM t_types;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLGetData(stmt, 1, SQL_C_CHAR, buf, sizeof(buf), &ind));
        VERIFY(ind == SQL_NULL_DATA);
        VERIFY(buf[0] == '#');
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 5. Troncamento: buffer piu' corto del valore.
     *    Deve arrivare SQL_SUCCESS_WITH_INFO con SQLSTATE 01004, il buffer
     *    deve restare terminato e l'indicatore riportare la lunghezza intera.
     * ---------------------------------------------------------------- */
    {
        char small[5]; SQLLEN ind = 0; SQLRETURN rc;
        SQLCHAR state[6] = ""; SQLCHAR msg[256] = "";
        SQLINTEGER native = 0; SQLSMALLINT len = 0;

        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT txt FROM t_types;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        memset(small, '#', sizeof(small));
        rc = SQLGetData(stmt, 1, SQL_C_CHAR, small, sizeof(small), &ind);
        VERIFY(rc == SQL_SUCCESS_WITH_INFO);
        VERIFY(small[sizeof(small) - 1] == '\0');
        VERIFY(strlen(small) == sizeof(small) - 1);
        VERIFY(ind == 10);                    /* 'abcdefghij' */
        if (SQLGetDiagRec(SQL_HANDLE_STMT, stmt, 1, state, &native, msg, sizeof(msg), &len)
                == SQL_SUCCESS) {
            VERIFY(!strcmp((char *)state, "01004"));
        } else {
            fprintf(stderr, "FAIL: nessuna diagnostica dopo il troncamento\n");
            cs_failures++;
        }
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    /* ---------------------------------------------------------------- *
     * 6. SQLGetData a blocchi ripetuti sulla stessa colonna: e' il modo in cui
     *    un'applicazione legge un valore piu' lungo del proprio buffer.
     * ---------------------------------------------------------------- */
    {
        char part[4]; char joined[32]; SQLLEN ind = 0; SQLRETURN rc; size_t used = 0;

        joined[0] = '\0';
        CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
            (SQLCHAR *)"SELECT txt FROM t_types;", SQL_NTS));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFetch(stmt));
        for (;;) {
            rc = SQLGetData(stmt, 1, SQL_C_CHAR, part, sizeof(part), &ind);
            if (rc == SQL_NO_DATA) break;
            if (!SQL_SUCCEEDED(rc)) { fprintf(stderr, "FAIL: SQLGetData a blocchi rc=%d\n", rc); cs_failures++; break; }
            if (used + strlen(part) < sizeof(joined)) { strcpy(joined + used, part); used += strlen(part); }
            if (rc == SQL_SUCCESS) break;     /* ultimo pezzo */
        }
        VERIFY(!strcmp(joined, "abcdefghij"));
        CHECKED(SQL_HANDLE_STMT, stmt, SQLFreeStmt(stmt, SQL_CLOSE));
    }

    CHECKED(SQL_HANDLE_STMT, stmt, SQLExecDirect(stmt,
        (SQLCHAR *)"DROP TABLE IF EXISTS t_types;", SQL_NTS));
    cs_test_close(env, dbc, stmt);
    return cs_test_report("types");
}
