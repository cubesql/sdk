#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <odbcinst.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CS_DRIVER_NAME "CubeSQL ODBC Driver"

typedef struct setup_options {
    char dsn[256];
    char description[512];
    char server[256];
    char port[16];
    char uid[256];
    char database[512];
    char encryption[32];
    char timeout[16];
} setup_options;

static int key_equal(const char *a, const char *b) {
    return _stricmp(a, b) == 0;
}

static void set_value(char *out, size_t cap, const char *value) {
    size_t n = strlen(value);
    if (n >= cap) n = cap - 1;
    memcpy(out, value, n); out[n] = 0;
}

static void parse_attributes(setup_options *o, const char *attributes) {
    const char *p = attributes;
    while (p && *p) {
        const char *eq = strchr(p, '=');
        size_t keylen;
        char key[64];
        if (!eq) { p += strlen(p) + 1; continue; }
        keylen = (size_t)(eq - p);
        if (keylen >= sizeof(key)) keylen = sizeof(key) - 1;
        memcpy(key, p, keylen); key[keylen] = 0;
        if (key_equal(key, "DSN")) set_value(o->dsn, sizeof(o->dsn), eq + 1);
        else if (key_equal(key, "Description")) set_value(o->description, sizeof(o->description), eq + 1);
        else if (key_equal(key, "Server") || key_equal(key, "Host")) set_value(o->server, sizeof(o->server), eq + 1);
        else if (key_equal(key, "Port")) set_value(o->port, sizeof(o->port), eq + 1);
        else if (key_equal(key, "UID") || key_equal(key, "User")) set_value(o->uid, sizeof(o->uid), eq + 1);
        else if (key_equal(key, "Database")) set_value(o->database, sizeof(o->database), eq + 1);
        else if (key_equal(key, "Encryption")) set_value(o->encryption, sizeof(o->encryption), eq + 1);
        else if (key_equal(key, "Timeout")) set_value(o->timeout, sizeof(o->timeout), eq + 1);
        p += strlen(p) + 1;
    }
}

static void read_existing(setup_options *o) {
#define READ_OPTION(key, member, fallback) \
    SQLGetPrivateProfileString(o->dsn, key, fallback, o->member, (int)sizeof(o->member), "ODBC.INI")
    if (!o->dsn[0]) return;
    READ_OPTION("Description", description, "");
    READ_OPTION("Server", server, "localhost");
    READ_OPTION("Port", port, "4430");
    READ_OPTION("UID", uid, "");
    READ_OPTION("Database", database, "");
    READ_OPTION("Encryption", encryption, "AES256");
    READ_OPTION("Timeout", timeout, "12");
#undef READ_OPTION
}

static BOOL write_options(const char *driver, const setup_options *o) {
    if (!SQLValidDSN(o->dsn) || !SQLWriteDSNToIni(o->dsn, driver)) return FALSE;
#define WRITE_OPTION(key, member) \
    if (!SQLWritePrivateProfileString(o->dsn, key, o->member, "ODBC.INI")) return FALSE
    WRITE_OPTION("Description", description);
    WRITE_OPTION("Server", server);
    WRITE_OPTION("Port", port);
    WRITE_OPTION("UID", uid);
    WRITE_OPTION("Database", database);
    WRITE_OPTION("Encryption", encryption);
    WRITE_OPTION("Timeout", timeout);
#undef WRITE_OPTION
    return TRUE;
}

__declspec(dllexport) BOOL INSTAPI ConfigDSN(HWND parent, WORD request,
                                             LPCSTR driver, LPCSTR attributes) {
    setup_options o;
    memset(&o, 0, sizeof(o));
    parse_attributes(&o, attributes);
    if (request == ODBC_REMOVE_DSN || request == ODBC_REMOVE_SYS_DSN)
        return o.dsn[0] ? SQLRemoveDSNFromIni(o.dsn) : FALSE;
    if (request != ODBC_ADD_DSN && request != ODBC_CONFIG_DSN &&
        request != ODBC_ADD_SYS_DSN && request != ODBC_CONFIG_SYS_DSN) return FALSE;
    if (request == ODBC_CONFIG_DSN || request == ODBC_CONFIG_SYS_DSN) {
        setup_options supplied = o;
        read_existing(&o);
        parse_attributes(&o, attributes);
        if (supplied.dsn[0]) set_value(o.dsn, sizeof(o.dsn), supplied.dsn);
    }
    if (!o.dsn[0]) {
        if (parent) MessageBoxA(parent,
            "A DSN name is required. Configure CubeSQL DSNs with odbcconf.exe "
            "or the supplied install.ps1 script.", CS_DRIVER_NAME, MB_OK | MB_ICONINFORMATION);
        return FALSE;
    }
    if (!o.server[0]) strcpy(o.server, "localhost");
    if (!o.port[0]) strcpy(o.port, "4430");
    if (!o.encryption[0]) strcpy(o.encryption, "AES256");
    if (!o.timeout[0]) strcpy(o.timeout, "12");
    return write_options(driver && *driver ? driver : CS_DRIVER_NAME, &o);
}

__declspec(dllexport) BOOL INSTAPI ConfigDriver(HWND parent, WORD request,
    LPCSTR driver, LPCSTR args, LPSTR message, WORD capacity, WORD *length) {
    const char *result = "CubeSQL ODBC Driver 1.0";
    size_t n = strlen(result);
    (void)parent; (void)driver; (void)args;
    if (request != ODBC_INSTALL_DRIVER && request != ODBC_CONFIG_DRIVER &&
        request != ODBC_REMOVE_DRIVER) return FALSE;
    if (length) *length = (WORD)n;
    if (message && capacity) {
        size_t room = (size_t)capacity - 1;
        size_t copy = n < room ? n : room;
        memcpy(message, result, copy); message[copy] = 0;
    }
    return TRUE;
}
#endif
