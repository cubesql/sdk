/*
 * Impalcatura condivisa dalle suite che compilano il driver dentro
 * l'eseguibile e lo chiamano direttamente, senza Driver Manager.
 *
 * Su Windows le dichiarazioni delle funzioni ODBC arrivano gia' da sql.h e
 * sqlext.h attraverso cubesql_odbc.h, quindi qui non si ridichiara nulla:
 * servono solo le macro di verifica e l'apertura della connessione.
 */
#ifndef CUBESQL_ODBC_TEST_COMMON_H
#define CUBESQL_ODBC_TEST_COMMON_H

#include "cubesql_odbc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cs_failures = 0;

#define VERIFY(x) do { \
    if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); cs_failures++; } \
} while (0)

/* Come VERIFY ma stampa anche la diagnostica del driver. */
#define CHECKED(type, handle, call) do { \
    SQLRETURN cs_rc_ = (call); \
    if (!SQL_SUCCEEDED(cs_rc_)) { \
        SQLCHAR cs_st_[6] = "", cs_msg_[512] = ""; \
        SQLINTEGER cs_native_ = 0; SQLSMALLINT cs_len_ = 0; \
        SQLGetDiagRec((type), (handle), 1, cs_st_, &cs_native_, cs_msg_, sizeof(cs_msg_), &cs_len_); \
        fprintf(stderr, "FAIL %s:%d: %s -> rc=%d [%s] %s\n", \
            __FILE__, __LINE__, #call, (int)cs_rc_, cs_st_, cs_msg_); \
        cs_failures++; \
    } \
} while (0)

static void cs_test_conn_string(char *out, size_t cap, const char *extra) {
    const char *host = getenv("CUBESQL_ODBC_HOST");
    const char *port = getenv("CUBESQL_ODBC_PORT");
    const char *user = getenv("CUBESQL_ODBC_USER");
    const char *pass = getenv("CUBESQL_ODBC_PASSWORD");
    if (!host) host = "127.0.0.1";
    if (!port) port = "4430";
    if (!user) user = "admin";
    if (!pass) pass = "admin";
    snprintf(out, cap,
        "DRIVER={CubeSQL ODBC Driver};SERVER={%s};PORT=%s;UID={%s};PWD={%s};"
        "ENCRYPTION=NONE;TIMEOUT=12;%s",
        host, port, user, pass, extra ? extra : "");
}

/*
 * Apre ambiente e connessione e prepara un database di lavoro. Restituisce 0
 * se il server non e' raggiungibile, cosi' la suite puo' dirlo e non fallire
 * per un motivo che non riguarda il driver.
 */
static int cs_test_open(SQLHENV *env, SQLHDBC *dbc, SQLHSTMT *stmt,
                        const char *database, const char *extra) {
    char conn[1024], sql[256];
    SQLRETURN rc;

    *env = SQL_NULL_HENV; *dbc = SQL_NULL_HDBC; *stmt = SQL_NULL_HSTMT;
    cs_test_conn_string(conn, sizeof(conn), extra);

    if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, env))) return 0;
    SQLSetEnvAttr(*env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)(uintptr_t)SQL_OV_ODBC3, 0);
    if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_DBC, *env, dbc))) return 0;

    rc = SQLDriverConnect(*dbc, NULL, (SQLCHAR *)conn, SQL_NTS, NULL, 0, NULL,
                          SQL_DRIVER_NOPROMPT);
    if (!SQL_SUCCEEDED(rc)) {
        fprintf(stderr, "server non raggiungibile: la suite non puo' girare\n");
        return 0;
    }
    if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, *dbc, stmt))) return 0;

    if (getenv("CUBESQL_ODBC_REGISTER_TEST_SERVER")) {
        SQLExecDirect(*stmt, (SQLCHAR *)"SET REGISTRATION TO 'SQLabs srl' WITH KEY "
            "'CSQL75ZZ-PPJHAG9L-27X2W3C4-8DX6BAXX-35XBX46W';", SQL_NTS);
        SQLFreeStmt(*stmt, SQL_CLOSE);
    }
    snprintf(sql, sizeof(sql), "CREATE DATABASE %s IF NOT EXISTS;", database);
    SQLExecDirect(*stmt, (SQLCHAR *)sql, SQL_NTS);
    SQLFreeStmt(*stmt, SQL_CLOSE);
    snprintf(sql, sizeof(sql), "USE DATABASE %s;", database);
    if (!SQL_SUCCEEDED(SQLExecDirect(*stmt, (SQLCHAR *)sql, SQL_NTS))) return 0;
    SQLFreeStmt(*stmt, SQL_CLOSE);
    return 1;
}

static void cs_test_close(SQLHENV env, SQLHDBC dbc, SQLHSTMT stmt) {
    if (stmt) SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    if (dbc) { SQLDisconnect(dbc); SQLFreeHandle(SQL_HANDLE_DBC, dbc); }
    if (env) SQLFreeHandle(SQL_HANDLE_ENV, env);
}

static int cs_test_report(const char *name) {
    if (cs_failures) {
        fprintf(stderr, "CubeSQL ODBC %s: %d controlli falliti\n", name, cs_failures);
        return 1;
    }
    printf("CubeSQL ODBC %s: PASS\n", name);
    return 0;
}

#endif
