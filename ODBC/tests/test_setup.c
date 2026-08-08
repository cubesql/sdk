/*
 * Pannello di configurazione: setup.c, 429 righe che nessun test toccava.
 *
 * ConfigDSN e' il punto d'ingresso di tutta la configurazione dei DSN - cioe'
 * il reclamo numero uno del cliente - e con hwndParent nullo lavora senza
 * interfaccia, che e' il modo in cui la guidano odbcconf e gli installer
 * non presidiati. Quindi e' testabile per intero, senza aprire finestre.
 *
 * Scrive un DSN utente (HKCU), quindi non servono privilegi elevati.
 */
#include "test_common.h"
#include <odbcinst.h>

#define TEST_DSN "cs_setup_test"

static void dump_installer_error(const char *what) {
    SQLCHAR msg[512] = "";
    SQLINTEGER code = 0;
    SQLSMALLINT len = 0;
    if (SQLInstallerError(1, &code, msg, sizeof(msg), &len) == SQL_SUCCESS)
        fprintf(stderr, "  (%s: %ld %s)\n", what, (long)code, msg);
}

static int read_key(const char *key, char *out, int cap) {
    out[0] = '\0';
    return SQLGetPrivateProfileString(TEST_DSN, key, "", out, cap, "ODBC.INI");
}

int main(void) {
    /* attributi separati da NUL e terminati da doppio NUL, come vuole ODBC */
    static const char add_attrs[] =
        "DSN=" TEST_DSN "\0"
        "SERVER=127.0.0.1\0"
        "PORT=4430\0"
        "UID=admin\0"
        "DATABASE=odbc_setup.db\0"
        "ENCRYPTION=NONE\0"
        "TIMEOUT=12\0";
    static const char config_attrs[] =
        "DSN=" TEST_DSN "\0"
        "SERVER=localhost\0"
        "PORT=4431\0"
        "TIMEOUT=30\0";
    static const char remove_attrs[] = "DSN=" TEST_DSN "\0";
    static const char noname_attrs[] = "SERVER=127.0.0.1\0";

    char value[256];
    BOOL ok;

    /*
     * Il database a cui il DSN puntera' deve esistere, altrimenti la prova di
     * connessione fallirebbe per un motivo che non riguarda ConfigDSN. Questa
     * apertura serve anche a saltare la suite con un messaggio chiaro quando il
     * server non c'e'.
     */
    {
        SQLHENV e; SQLHDBC d; SQLHSTMT s;
        if (!cs_test_open(&e, &d, &s, "odbc_setup.db", "")) return 2;
        cs_test_close(e, d, s);
    }

    /* si parte da pulito, anche se un giro precedente si fosse interrotto */
    ConfigDSN(NULL, ODBC_REMOVE_DSN, "CubeSQL ODBC Driver", remove_attrs);

    /* ---------------------------------------------------------------- *
     * 1. Creazione senza interfaccia.
     * ---------------------------------------------------------------- */
    ok = ConfigDSN(NULL, ODBC_ADD_DSN, "CubeSQL ODBC Driver", add_attrs);
    if (!ok) { fprintf(stderr, "FAIL: ConfigDSN ODBC_ADD_DSN\n"); dump_installer_error("add"); cs_failures++; }

    VERIFY(read_key("Server", value, sizeof(value)) > 0);
    VERIFY(!strcmp(value, "127.0.0.1"));
    VERIFY(read_key("Port", value, sizeof(value)) > 0);
    VERIFY(!strcmp(value, "4430"));
    VERIFY(read_key("UID", value, sizeof(value)) > 0);
    VERIFY(!strcmp(value, "admin"));
    VERIFY(read_key("Database", value, sizeof(value)) > 0);
    VERIFY(!strcmp(value, "odbc_setup.db"));
    VERIFY(read_key("Timeout", value, sizeof(value)) > 0);
    VERIFY(!strcmp(value, "12"));

    /* la password non deve mai finire nel DSN */
    read_key("PWD", value, sizeof(value));
    VERIFY(value[0] == '\0');
    read_key("Password", value, sizeof(value));
    VERIFY(value[0] == '\0');

    /* ---------------------------------------------------------------- *
     * 2. Il DSN appena scritto deve essere utilizzabile per connettersi.
     * ---------------------------------------------------------------- */
    {
        SQLHENV env = SQL_NULL_HENV; SQLHDBC dbc = SQL_NULL_HDBC;
        char conn[256];
        SQLRETURN rc;

        snprintf(conn, sizeof(conn), "DSN=%s;PWD=admin;", TEST_DSN);
        if (SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env))) {
            SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)(uintptr_t)SQL_OV_ODBC3, 0);
            SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);
            rc = SQLDriverConnect(dbc, NULL, (SQLCHAR *)conn, SQL_NTS, NULL, 0, NULL,
                                  SQL_DRIVER_NOPROMPT);
            if (!SQL_SUCCEEDED(rc)) {
                fprintf(stderr, "FAIL: il DSN scritto da ConfigDSN non si connette\n");
                cs_failures++;
            } else {
                SQLDisconnect(dbc);
            }
            if (dbc) SQLFreeHandle(SQL_HANDLE_DBC, dbc);
            SQLFreeHandle(SQL_HANDLE_ENV, env);
        }
    }

    /* ---------------------------------------------------------------- *
     * 3. Modifica: i valori indicati cambiano, gli altri restano.
     * ---------------------------------------------------------------- */
    ok = ConfigDSN(NULL, ODBC_CONFIG_DSN, "CubeSQL ODBC Driver", config_attrs);
    if (!ok) { fprintf(stderr, "FAIL: ConfigDSN ODBC_CONFIG_DSN\n"); dump_installer_error("config"); cs_failures++; }
    VERIFY(read_key("Server", value, sizeof(value)) > 0);
    VERIFY(!strcmp(value, "localhost"));
    VERIFY(read_key("Port", value, sizeof(value)) > 0);
    VERIFY(!strcmp(value, "4431"));
    VERIFY(read_key("Timeout", value, sizeof(value)) > 0);
    VERIFY(!strcmp(value, "30"));
    /* non toccati dalla modifica: devono sopravvivere */
    VERIFY(read_key("UID", value, sizeof(value)) > 0);
    VERIFY(!strcmp(value, "admin"));
    VERIFY(read_key("Database", value, sizeof(value)) > 0);
    VERIFY(!strcmp(value, "odbc_setup.db"));

    /* ---------------------------------------------------------------- *
     * 4. Casi d'errore: devono rispondere FALSE, non scrivere a caso.
     * ---------------------------------------------------------------- */
    ok = ConfigDSN(NULL, ODBC_ADD_DSN, "CubeSQL ODBC Driver", noname_attrs);
    VERIFY(ok == FALSE);                       /* manca il nome del DSN */
    ok = ConfigDSN(NULL, 999, "CubeSQL ODBC Driver", add_attrs);
    VERIFY(ok == FALSE);                       /* richiesta sconosciuta */
    ok = ConfigDSN(NULL, ODBC_REMOVE_DSN, "CubeSQL ODBC Driver", noname_attrs);
    VERIFY(ok == FALSE);                       /* rimozione senza nome */

    /* ---------------------------------------------------------------- *
     * 5. Rimozione, e verifica che sia sparito davvero.
     * ---------------------------------------------------------------- */
    ok = ConfigDSN(NULL, ODBC_REMOVE_DSN, "CubeSQL ODBC Driver", remove_attrs);
    if (!ok) { fprintf(stderr, "FAIL: ConfigDSN ODBC_REMOVE_DSN\n"); dump_installer_error("remove"); cs_failures++; }
    read_key("Server", value, sizeof(value));
    VERIFY(value[0] == '\0');

    /* ---------------------------------------------------------------- *
     * 6. La variante Unicode deve fare lo stesso lavoro.
     * ---------------------------------------------------------------- */
    {
        static const wchar_t wadd[] =
            L"DSN=cs_setup_test\0"
            L"SERVER=127.0.0.1\0"
            L"PORT=4430\0"
            L"UID=admin\0"
            L"DATABASE=odbc_setup.db\0";
        static const wchar_t wremove[] = L"DSN=cs_setup_test\0";

        ok = ConfigDSNW(NULL, ODBC_ADD_DSN, L"CubeSQL ODBC Driver", wadd);
        if (!ok) { fprintf(stderr, "FAIL: ConfigDSNW ODBC_ADD_DSN\n"); dump_installer_error("addW"); cs_failures++; }
        VERIFY(read_key("Server", value, sizeof(value)) > 0);
        VERIFY(!strcmp(value, "127.0.0.1"));

        ok = ConfigDSNW(NULL, ODBC_REMOVE_DSN, L"CubeSQL ODBC Driver", wremove);
        if (!ok) { fprintf(stderr, "FAIL: ConfigDSNW ODBC_REMOVE_DSN\n"); dump_installer_error("removeW"); cs_failures++; }
        read_key("Server", value, sizeof(value));
        VERIFY(value[0] == '\0');
    }

    /* ---------------------------------------------------------------- *
     * 7. ConfigDriver: richieste sconosciute devono essere respinte senza
     *    effetti collaterali.
     * ---------------------------------------------------------------- */
    {
        WORD written = 0;
        char msg[256] = "";
        ok = ConfigDriver(NULL, 999, "CubeSQL ODBC Driver", "", msg, sizeof(msg), &written);
        VERIFY(ok == FALSE);
    }

    return cs_test_report("setup");
}
