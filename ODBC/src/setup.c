/*
 * Windows setup entry points for the CubeSQL ODBC driver.
 *
 * ConfigDSN/ConfigDSNW drive the modal dialog the ODBC Data Source
 * Administrator shows when a user adds or configures a data source, and
 * cs_prompt_dialog is the login prompt SQLDriverConnect puts up when the
 * Driver Manager asks for one.
 *
 * The previous release had neither: ConfigDSN wrote the registry directly and,
 * when invoked interactively, only put up a message box telling the user to go
 * and run odbcconf.exe instead.
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <odbcinst.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cubesql_odbc.h"
#include "cubesql_odbc_resource.h"

#define CS_DRIVER_NAME "CubeSQL ODBC Driver"

static const char *const cs_encryption_names[] = {
    "NONE", "AES128", "AES192", "AES256",
    "SSL", "SSL+AES128", "SSL+AES192", "SSL+AES256"
};

typedef struct cs_dialog_state {
    cs_conn_options *options;
    char *description;          /* NULL in login mode */
    size_t description_cap;
    int connect_mode;           /* 1 = login prompt, 0 = DSN editor */
} cs_dialog_state;

static void cs_set_text(HWND dialog, int control, const char *value) {
    SetDlgItemTextA(dialog, control, value ? value : "");
}

static void cs_get_text(HWND dialog, int control, char *out, size_t cap) {
    if (cap == 0) return;
    if (!GetDlgItemTextA(dialog, control, out, (int)cap)) out[0] = '\0';
    out[cap - 1] = '\0';
}

static void cs_status(HWND dialog, const char *text) {
    cs_set_text(dialog, IDC_STATUS, text);
}

/*
 * Opens a connection with whatever the dialog currently holds. Returns 0 on
 * success, otherwise fills "error" with the server's message.
 */
static int cs_try_connect(const cs_conn_options *o, csqldb **out,
                          char *error, size_t error_cap) {
    csqldb *db = NULL;
    int port = atoi(o->port[0] ? o->port : "4430");
    int timeout = atoi(o->timeout[0] ? o->timeout : "12");
    int encryption = cs_encryption_value(o->encryption);
    int rc;

    if (out) *out = NULL;
    if (port < 1 || port > 65535) {
        snprintf(error, error_cap, "Port must be between 1 and 65535.");
        return -1;
    }
    if (encryption < 0) {
        snprintf(error, error_cap, "Unsupported encryption mode '%s'.", o->encryption);
        return -1;
    }
    if (!o->user[0]) {
        snprintf(error, error_cap, "A user name is required.");
        return -1;
    }
    rc = cubesql_connect(&db, o->host[0] ? o->host : "localhost", port,
                         o->user, o->password, timeout, encryption);
    if (rc != CUBESQL_NOERR) {
        const char *message = db ? cubesql_errmsg(db) : NULL;
        snprintf(error, error_cap, "%s", (message && *message) ? message : "Connection failed.");
        if (db) cubesql_disconnect(db, kFALSE);
        return -1;
    }
    if (o->database[0]) {
        rc = cubesql_set_database(db, o->database);
        if (rc != CUBESQL_NOERR) {
            const char *message = cubesql_errmsg(db);
            snprintf(error, error_cap, "%s", (message && *message) ? message : "Cannot select the database.");
            cubesql_disconnect(db, kTRUE);
            return -1;
        }
    }
    if (out) *out = db;
    else cubesql_disconnect(db, kTRUE);
    return 0;
}

static void cs_read_dialog(HWND dialog, cs_dialog_state *state, cs_conn_options *o) {
    memset(o, 0, sizeof(*o));
    if (!state->connect_mode) {
        cs_get_text(dialog, IDC_DSN, o->dsn, sizeof(o->dsn));
        if (state->description && state->description_cap)
            cs_get_text(dialog, IDC_DESCRIPTION, state->description, state->description_cap);
    }
    cs_get_text(dialog, IDC_SERVER, o->host, sizeof(o->host));
    cs_get_text(dialog, IDC_PORT, o->port, sizeof(o->port));
    cs_get_text(dialog, IDC_USER, o->user, sizeof(o->user));
    cs_get_text(dialog, IDC_PASSWORD, o->password, sizeof(o->password));
    cs_get_text(dialog, IDC_DATABASE, o->database, sizeof(o->database));
    cs_get_text(dialog, IDC_ENCRYPTION, o->encryption, sizeof(o->encryption));
    cs_get_text(dialog, IDC_TIMEOUT, o->timeout, sizeof(o->timeout));
}

/* Fills the database combo from the server the dialog currently points at. */
static void cs_refresh_databases(HWND dialog, cs_dialog_state *state) {
    cs_conn_options probe;
    csqldb *db = NULL;
    char error[512] = "";
    char current[512];
    csqlc *cursor;

    cs_read_dialog(dialog, state, &probe);
    probe.database[0] = '\0';
    cs_get_text(dialog, IDC_DATABASE, current, sizeof(current));

    cs_status(dialog, "Connecting...");
    if (cs_try_connect(&probe, &db, error, sizeof(error)) != 0) {
        cs_status(dialog, error);
        return;
    }
    cursor = cubesql_select(db, "SHOW DATABASES;", kFALSE);
    SendDlgItemMessageA(dialog, IDC_DATABASE, CB_RESETCONTENT, 0, 0);
    if (cursor) {
        int rows = cubesql_cursor_numrows(cursor), row;
        for (row = 1; row <= rows; row++) {
            char *name = cubesql_cursor_cstring(cursor, row, 1);
            if (!name) continue;
            SendDlgItemMessageA(dialog, IDC_DATABASE, CB_ADDSTRING, 0, (LPARAM)name);
            free(name);
        }
        cubesql_cursor_free(cursor);
        cs_status(dialog, "Database list updated.");
    } else {
        cubesql_clear_errors(db);
        cs_status(dialog, "Connected, but the database list is unavailable.");
    }
    cubesql_disconnect(db, kTRUE);
    cs_set_text(dialog, IDC_DATABASE, current);
}

static INT_PTR CALLBACK cs_dialog_proc(HWND dialog, UINT message,
                                       WPARAM wparam, LPARAM lparam) {
    cs_dialog_state *state = (cs_dialog_state *)GetWindowLongPtr(dialog, GWLP_USERDATA);
    size_t i;

    switch (message) {
        case WM_INITDIALOG: {
            cs_conn_options *o;
            state = (cs_dialog_state *)lparam;
            SetWindowLongPtr(dialog, GWLP_USERDATA, (LONG_PTR)state);
            o = state->options;
            for (i = 0; i < sizeof(cs_encryption_names) / sizeof(cs_encryption_names[0]); i++)
                SendDlgItemMessageA(dialog, IDC_ENCRYPTION, CB_ADDSTRING, 0,
                                    (LPARAM)cs_encryption_names[i]);
            if (!state->connect_mode) {
                cs_set_text(dialog, IDC_DSN, o->dsn);
                cs_set_text(dialog, IDC_DESCRIPTION, state->description);
                /* A DSN is renamed by creating a new one, so lock the name
                   when the administrator opened an existing data source. */
                if (o->dsn[0]) EnableWindow(GetDlgItem(dialog, IDC_DSN), FALSE);
            }
            cs_set_text(dialog, IDC_SERVER, o->host[0] ? o->host : "localhost");
            cs_set_text(dialog, IDC_PORT, o->port[0] ? o->port : "4430");
            cs_set_text(dialog, IDC_USER, o->user);
            cs_set_text(dialog, IDC_PASSWORD, o->password);
            cs_set_text(dialog, IDC_DATABASE, o->database);
            cs_set_text(dialog, IDC_TIMEOUT, o->timeout[0] ? o->timeout : "12");
            if (SendDlgItemMessageA(dialog, IDC_ENCRYPTION, CB_SELECTSTRING, (WPARAM)-1,
                                    (LPARAM)(o->encryption[0] ? o->encryption : "AES256")) == CB_ERR)
                SendDlgItemMessageA(dialog, IDC_ENCRYPTION, CB_SELECTSTRING, (WPARAM)-1,
                                    (LPARAM)"AES256");
            SetFocus(GetDlgItem(dialog,
                state->connect_mode ? IDC_PASSWORD :
                (o->dsn[0] ? IDC_SERVER : IDC_DSN)));
            return FALSE;
        }

        case WM_COMMAND:
            switch (LOWORD(wparam)) {
                case IDC_TEST: {
                    cs_conn_options probe;
                    char error[512] = "";
                    cs_read_dialog(dialog, state, &probe);
                    cs_status(dialog, "Connecting...");
                    if (cs_try_connect(&probe, NULL, error, sizeof(error)) == 0) {
                        MessageBoxA(dialog, "Connection successful.", CS_DRIVER_NAME,
                                    MB_OK | MB_ICONINFORMATION);
                        cs_status(dialog, "Connection successful.");
                    } else {
                        MessageBoxA(dialog, error, CS_DRIVER_NAME, MB_OK | MB_ICONEXCLAMATION);
                        cs_status(dialog, "Connection failed.");
                    }
                    return TRUE;
                }
                case IDC_REFRESH_DATABASES:
                    cs_refresh_databases(dialog, state);
                    return TRUE;
                case IDOK: {
                    cs_conn_options entered;
                    cs_read_dialog(dialog, state, &entered);
                    if (!state->connect_mode && !entered.dsn[0]) {
                        MessageBoxA(dialog, "Enter a data source name.", CS_DRIVER_NAME,
                                    MB_OK | MB_ICONEXCLAMATION);
                        SetFocus(GetDlgItem(dialog, IDC_DSN));
                        return TRUE;
                    }
                    if (!state->connect_mode && !SQLValidDSN(entered.dsn)) {
                        MessageBoxA(dialog,
                            "That data source name contains a character ODBC does not allow.",
                            CS_DRIVER_NAME, MB_OK | MB_ICONEXCLAMATION);
                        SetFocus(GetDlgItem(dialog, IDC_DSN));
                        return TRUE;
                    }
                    if (cs_encryption_value(entered.encryption) < 0) {
                        MessageBoxA(dialog, "Select a supported encryption mode.",
                                    CS_DRIVER_NAME, MB_OK | MB_ICONEXCLAMATION);
                        return TRUE;
                    }
                    *state->options = entered;
                    cs_conn_apply_defaults(state->options);
                    EndDialog(dialog, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                    EndDialog(dialog, IDCANCEL);
                    return TRUE;
                default:
                    break;
            }
            break;

        case WM_CLOSE:
            EndDialog(dialog, IDCANCEL);
            return TRUE;

        default:
            break;
    }
    return FALSE;
}

static int cs_run_dialog(HWND parent, cs_conn_options *o, int connect_mode,
                         char *description, size_t description_cap) {
    cs_dialog_state state;
    INT_PTR result;
    state.options = o;
    state.description = description;
    state.description_cap = description_cap;
    state.connect_mode = connect_mode;
    result = DialogBoxParamA(cs_dll_module,
        MAKEINTRESOURCEA(connect_mode ? IDD_CUBESQL_LOGIN : IDD_CUBESQL_DSN),
        parent, cs_dialog_proc, (LPARAM)&state);
    return result == IDOK;
}

int cs_prompt_dialog(HWND parent, cs_conn_options *o, int connect_mode) {
    return cs_run_dialog(parent, o, connect_mode, NULL, 0);
}

/* ------------------------------------------------------------------ */
/* DSN persistence                                                     */
/* ------------------------------------------------------------------ */

static int cs_key_equal(const char *a, const char *b) { return _stricmp(a, b) == 0; }

/*
 * ConfigDSN receives its attributes as a double-NUL terminated list of
 * "key=value" pairs, not as a connection string.
 */
static void cs_parse_attributes(cs_conn_options *o, const char *attributes) {
    const char *p = attributes;
    while (p && *p) {
        const char *eq = strchr(p, '=');
        size_t keylen;
        char key[64];
        if (!eq) { p += strlen(p) + 1; continue; }
        keylen = (size_t)(eq - p);
        if (keylen >= sizeof(key)) keylen = sizeof(key) - 1;
        memcpy(key, p, keylen); key[keylen] = 0;
        if (cs_key_equal(key, "DSN")) cs_option_set(o->dsn, sizeof(o->dsn), eq + 1);
        else if (cs_key_equal(key, "Server") || cs_key_equal(key, "Host"))
            cs_option_set(o->host, sizeof(o->host), eq + 1);
        else if (cs_key_equal(key, "Port")) cs_option_set(o->port, sizeof(o->port), eq + 1);
        else if (cs_key_equal(key, "UID") || cs_key_equal(key, "User"))
            cs_option_set(o->user, sizeof(o->user), eq + 1);
        else if (cs_key_equal(key, "PWD") || cs_key_equal(key, "Password"))
            cs_option_set(o->password, sizeof(o->password), eq + 1);
        else if (cs_key_equal(key, "Database") || cs_key_equal(key, "DB"))
            cs_option_set(o->database, sizeof(o->database), eq + 1);
        else if (cs_key_equal(key, "Encryption") || cs_key_equal(key, "Enc"))
            cs_option_set(o->encryption, sizeof(o->encryption), eq + 1);
        else if (cs_key_equal(key, "Timeout"))
            cs_option_set(o->timeout, sizeof(o->timeout), eq + 1);
        p += strlen(p) + 1;
    }
}

static void cs_read_dsn_description(const char *dsn, char *out, size_t cap) {
    SQLGetPrivateProfileString(dsn, "Description", "", out, (int)cap, "ODBC.INI");
}

static void cs_read_existing(cs_conn_options *o, char *description, size_t description_cap) {
    char buffer[1024];
#define CS_READ(key, member, fallback) do { \
    SQLGetPrivateProfileString(o->dsn, key, fallback, buffer, (int)sizeof(buffer), "ODBC.INI"); \
    if (!o->member[0] && buffer[0]) cs_option_set(o->member, sizeof(o->member), buffer); \
} while (0)
    if (!o->dsn[0]) return;
    cs_read_dsn_description(o->dsn, description, description_cap);
    CS_READ("Server", host, "localhost");
    CS_READ("Port", port, "4430");
    CS_READ("UID", user, "");
    CS_READ("Database", database, "");
    CS_READ("Encryption", encryption, "AES256");
    CS_READ("Timeout", timeout, "12");
#undef CS_READ
}

static BOOL cs_write_options(const char *driver, const cs_conn_options *o,
                             const char *description) {
    if (!SQLValidDSN(o->dsn)) return FALSE;
    if (!SQLWriteDSNToIni(o->dsn, driver)) return FALSE;
#define CS_WRITE(key, value) \
    if (!SQLWritePrivateProfileString(o->dsn, key, value, "ODBC.INI")) return FALSE
    CS_WRITE("Description", description ? description : "");
    CS_WRITE("Server", o->host);
    CS_WRITE("Port", o->port);
    CS_WRITE("UID", o->user);
    CS_WRITE("Database", o->database);
    CS_WRITE("Encryption", o->encryption);
    CS_WRITE("Timeout", o->timeout);
#undef CS_WRITE
    /* Passwords are deliberately never stored in a DSN. */
    return TRUE;
}

BOOL INSTAPI ConfigDSN(HWND parent, WORD request, LPCSTR driver, LPCSTR attributes) {
    cs_conn_options o;
    char description[512] = "";
    const char *driver_name = (driver && *driver) ? driver : CS_DRIVER_NAME;

    memset(&o, 0, sizeof(o));
    cs_parse_attributes(&o, attributes);

    if (request == ODBC_REMOVE_DSN || request == ODBC_REMOVE_SYS_DSN) {
        if (!o.dsn[0]) {
            SQLPostInstallerError(ODBC_ERROR_INVALID_KEYWORD_VALUE,
                                  "A data source name is required to remove a DSN.");
            return FALSE;
        }
        return SQLRemoveDSNFromIni(o.dsn);
    }
    if (request != ODBC_ADD_DSN && request != ODBC_CONFIG_DSN &&
        request != ODBC_ADD_SYS_DSN && request != ODBC_CONFIG_SYS_DSN) {
        SQLPostInstallerError(ODBC_ERROR_INVALID_REQUEST_TYPE,
                              "Unsupported ConfigDSN request.");
        return FALSE;
    }

    if (request == ODBC_CONFIG_DSN || request == ODBC_CONFIG_SYS_DSN)
        cs_read_existing(&o, description, sizeof(description));
    cs_conn_apply_defaults(&o);

    /*
     * A NULL window means the caller wants no user interface, which is how
     * odbcconf.exe and unattended installers drive ConfigDSN. Anything else
     * gets the dialog.
     */
    if (parent) {
        char edited_description[512];
        cs_option_set(edited_description, sizeof(edited_description), description);
        for (;;) {
            cs_conn_options confirmed = o;
            if (!cs_run_dialog(parent, &confirmed, 0, edited_description,
                               sizeof(edited_description)))
                return FALSE;
            o = confirmed;
            if (cs_write_options(driver_name, &o, edited_description)) return TRUE;
            if (MessageBoxA(parent,
                    "The data source could not be saved. Check that you have permission "
                    "to write this data source, then try again.",
                    CS_DRIVER_NAME, MB_RETRYCANCEL | MB_ICONEXCLAMATION) != IDRETRY)
                return FALSE;
        }
    }

    if (!o.dsn[0]) {
        SQLPostInstallerError(ODBC_ERROR_INVALID_KEYWORD_VALUE,
                              "A data source name is required.");
        return FALSE;
    }
    if (!cs_write_options(driver_name, &o, description)) {
        SQLPostInstallerError(ODBC_ERROR_REQUEST_FAILED,
                              "The data source could not be written.");
        return FALSE;
    }
    return TRUE;
}

/* The Unicode Driver Manager prefers ConfigDSNW when the driver exports it. */
BOOL INSTAPI ConfigDSNW(HWND parent, WORD request, LPCWSTR driver, LPCWSTR attributes) {
    char *driver_utf8 = NULL, *attributes_utf8 = NULL;
    size_t attributes_len = 0;
    BOOL result;

    if (driver) {
        int n = WideCharToMultiByte(CP_ACP, 0, driver, -1, NULL, 0, NULL, NULL);
        driver_utf8 = (char *)calloc(1, (size_t)(n > 0 ? n : 1));
        if (driver_utf8 && n > 0)
            WideCharToMultiByte(CP_ACP, 0, driver, -1, driver_utf8, n, NULL, NULL);
    }
    if (attributes) {
        /* Double-NUL terminated list: measure the whole block, not one string. */
        const WCHAR *p = attributes;
        size_t total = 0;
        while (*p) { size_t n = wcslen(p) + 1; total += n; p += n; }
        total += 1;
        {
            int n = WideCharToMultiByte(CP_ACP, 0, attributes, (int)total, NULL, 0, NULL, NULL);
            attributes_utf8 = (char *)calloc(1, (size_t)(n > 0 ? n : 1));
            if (attributes_utf8 && n > 0)
                WideCharToMultiByte(CP_ACP, 0, attributes, (int)total, attributes_utf8, n, NULL, NULL);
            attributes_len = (size_t)(n > 0 ? n : 0);
        }
    }
    (void)attributes_len;
    result = ConfigDSN(parent, request, driver_utf8, attributes_utf8);
    free(driver_utf8);
    free(attributes_utf8);
    return result;
}

BOOL INSTAPI ConfigDriver(HWND parent, WORD request, LPCSTR driver,
                          LPCSTR args, LPSTR message, WORD capacity, WORD *length) {
    const char *result = CSODBC_PRODUCT " " CSODBC_VERSION_STRING " (" CSODBC_ARCH_STRING ")";
    size_t n = strlen(result);
    (void)parent; (void)driver; (void)args;
    if (request != ODBC_INSTALL_DRIVER && request != ODBC_CONFIG_DRIVER &&
        request != ODBC_REMOVE_DRIVER) {
        SQLPostInstallerError(ODBC_ERROR_INVALID_REQUEST_TYPE,
                              "Unsupported ConfigDriver request.");
        return FALSE;
    }
    if (length) *length = (WORD)n;
    if (message && capacity) {
        size_t room = (size_t)capacity - 1;
        size_t copy = n < room ? n : room;
        memcpy(message, result, copy); message[copy] = 0;
    }
    return TRUE;
}
#endif
