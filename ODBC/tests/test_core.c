#include "cubesql_odbc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

SQLRETURN SQL_API SQLAllocHandle(SQLSMALLINT, SQLHANDLE, SQLHANDLE *);
SQLRETURN SQL_API SQLFreeHandle(SQLSMALLINT, SQLHANDLE);
SQLRETURN SQL_API SQLSetEnvAttr(SQLHENV, SQLINTEGER, SQLPOINTER, SQLINTEGER);
SQLRETURN SQL_API SQLGetEnvAttr(SQLHENV, SQLINTEGER, SQLPOINTER, SQLINTEGER, SQLINTEGER *);
SQLRETURN SQL_API SQLGetInfo(SQLHDBC, SQLUSMALLINT, SQLPOINTER, SQLSMALLINT,
    SQLSMALLINT *);
SQLRETURN SQL_API SQLGetInfoW(SQLHDBC, SQLUSMALLINT, SQLPOINTER, SQLSMALLINT,
    SQLSMALLINT *);
SQLRETURN SQL_API SQLGetFunctions(SQLHDBC, SQLUSMALLINT, SQLUSMALLINT *);
SQLRETURN SQL_API SQLDriverConnect(SQLHDBC, SQLHWND, SQLCHAR *, SQLSMALLINT,
    SQLCHAR *, SQLSMALLINT, SQLSMALLINT *, SQLUSMALLINT);
SQLRETURN SQL_API SQLGetDiagRec(SQLSMALLINT, SQLHANDLE, SQLSMALLINT, SQLCHAR *,
    SQLINTEGER *, SQLCHAR *, SQLSMALLINT, SQLSMALLINT *);

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", \
    __FILE__, __LINE__, #x); return 1; } } while (0)

int main(void) {
    SQLHENV env = SQL_NULL_HENV; SQLHDBC dbc = SQL_NULL_HDBC;
    SQLINTEGER version = 0, out_len = 0, native = 0; SQLSMALLINT len = 0;
    SQLCHAR state[6], message[512], driver_odbc_version[6]; SQLRETURN rc;
    SQLWCHAR wide_driver_odbc_version[6];
    SQLUSMALLINT supported = SQL_FALSE;
    SQLWCHAR sample[] = {'c', 'a', 'f', 0x00e9, 0};
    char *utf8;

    REQUIRE(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env) == SQL_SUCCESS);
    REQUIRE(SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION,
        (SQLPOINTER)(uintptr_t)SQL_OV_ODBC3_80, 0) == SQL_SUCCESS);
    REQUIRE(SQLGetEnvAttr(env, SQL_ATTR_ODBC_VERSION, &version,
        sizeof(version), &out_len) == SQL_SUCCESS);
    REQUIRE(version == SQL_OV_ODBC3_80);
    REQUIRE(SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc) == SQL_SUCCESS);
    REQUIRE(SQLGetInfo(dbc, SQL_DRIVER_ODBC_VER, driver_odbc_version,
        sizeof(driver_odbc_version), &len) == SQL_SUCCESS);
    REQUIRE(len == 5 && !strcmp((char *)driver_odbc_version,
        CSODBC_DRIVER_ODBC_VERSION));
    REQUIRE(SQLGetInfoW(dbc, SQL_DRIVER_ODBC_VER, wide_driver_odbc_version,
        sizeof(wide_driver_odbc_version), &len) == SQL_SUCCESS);
    REQUIRE(len == 5 * (SQLSMALLINT)sizeof(SQLWCHAR));
    {
        /*
         * Confrontata con la costante, non con "02.00" scritto a mano: la
         * versione dichiarata e' cambiata, e questo era l'unico punto del
         * sorgente che non la seguiva.
         */
        const char *expected = CSODBC_DRIVER_ODBC_VERSION;
        int i;
        for (i = 0; expected[i]; ++i)
            REQUIRE(wide_driver_odbc_version[i] == (SQLWCHAR)expected[i]);
        REQUIRE(wide_driver_odbc_version[i] == 0);
    }
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLALLOCCONNECT, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLALLOCENV, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    /*
     * SQLAllocHandle e' esportata dal driver, quindi va dichiarata supportata.
     * Questo controllo pretendeva SQL_FALSE, cioe' fotografava un difetto: la
     * tabella di SQLGetFunctions elencava solo gli identificatori ODBC 2.x, e
     * SQL_API_ODBC3_ALL_FUNCTIONS rispondeva percio' che mancavano
     * SQLAllocHandle, SQLFreeHandle, SQLGetDiagRec e le altre funzioni
     * fondamentali della 3.x, tutte presenti negli export.
     */
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLALLOCHANDLE, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLFREEHANDLE, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLGETDIAGREC, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLSETSTMTATTR, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    /*
     * I descrittori impliciti ora ci sono, e sono il prerequisito per
     * dichiarare ODBC 3.x: vanno dichiarati presenti, o il Driver Manager non
     * li userebbe. SQLCopyDesc no, e resta dichiarata assente: dire il falso
     * qui e' esattamente cio' che fa chiamare al Driver Manager un puntatore
     * che non esiste.
     */
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLGETDESCFIELD, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLSETDESCFIELD, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLGETDESCREC, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLSETDESCREC, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLCOPYDESC, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_FALSE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLALLOCSTMT, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLFREECONNECT, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLFREEENV, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);
    REQUIRE(SQLGetFunctions(dbc, SQL_API_SQLSETCONNECTOPTION, &supported) == SQL_SUCCESS);
    REQUIRE(supported == SQL_TRUE);

    rc = SQLDriverConnect(dbc, NULL, (SQLCHAR *)"BROKEN", SQL_NTS,
        NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    REQUIRE(rc == SQL_ERROR);
    REQUIRE(SQLGetDiagRec(SQL_HANDLE_DBC, dbc, 1, state, &native, message,
        sizeof(message), &len) == SQL_SUCCESS);
    REQUIRE(!strcmp((char *)state, "IM012"));

    rc = SQLDriverConnect(dbc, NULL,
        (SQLCHAR *)"SERVER=localhost;PORT=4430;", SQL_NTS,
        NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    REQUIRE(rc == SQL_ERROR);
    REQUIRE(SQLGetDiagRec(SQL_HANDLE_DBC, dbc, 1, state, &native, message,
        sizeof(message), &len) == SQL_SUCCESS);
    REQUIRE(!strcmp((char *)state, "28000"));

    utf8 = cs_utf16_to_utf8(sample, SQL_NTS);
    REQUIRE(utf8 != NULL && !strcmp(utf8, "caf\xc3\xa9"));
    free(utf8);

    REQUIRE(SQLFreeHandle(SQL_HANDLE_DBC, dbc) == SQL_SUCCESS);
    REQUIRE(SQLFreeHandle(SQL_HANDLE_ENV, env) == SQL_SUCCESS);
    puts("CubeSQL ODBC core: PASS");
    return 0;
}
