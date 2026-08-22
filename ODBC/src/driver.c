#include "cubesql_odbc.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <odbcinst.h>
#endif

void cs_mutex_init(cs_mutex *m) {
#ifdef _WIN32
    InitializeCriticalSection(m);
#else
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(m, &attr);
    pthread_mutexattr_destroy(&attr);
#endif
}

void cs_mutex_destroy(cs_mutex *m) {
#ifdef _WIN32
    DeleteCriticalSection(m);
#else
    pthread_mutex_destroy(m);
#endif
}

void cs_mutex_lock(cs_mutex *m) {
#ifdef _WIN32
    EnterCriticalSection(m);
#else
    pthread_mutex_lock(m);
#endif
}

void cs_mutex_unlock(cs_mutex *m) {
#ifdef _WIN32
    LeaveCriticalSection(m);
#else
    pthread_mutex_unlock(m);
#endif
}

int cs_mutex_trylock(cs_mutex *m) {
#ifdef _WIN32
    return TryEnterCriticalSection(m) ? 1 : 0;
#else
    return pthread_mutex_trylock(m) == 0;
#endif
}

/*
 * The Driver Manager does not serialise calls, so every entry point serialises
 * on the mutex owning its handle: statements share their connection's mutex,
 * because they share its socket. The mutex is recursive, so entry points that
 * call each other (SQLExecDirect -> SQLPrepare -> SQLExecute) nest safely.
 * Returns NULL for an invalid handle; the implementation then reports
 * SQL_INVALID_HANDLE itself.
 */
static cs_mutex *cs_handle_lock(SQLSMALLINT type, SQLHANDLE handle) {
    cs_handle *h = (cs_handle *)handle;
    if (!h || h->magic != CSODBC_MAGIC) return NULL;
    if (h->type != type) return NULL;
    if (type == SQL_HANDLE_ENV) return &((cs_env *)handle)->lock;
    if (type == SQL_HANDLE_DBC) return &((cs_dbc *)handle)->lock;
    if (type == SQL_HANDLE_STMT) return &((cs_stmt *)handle)->dbc->lock;
    return NULL;
}

static char *cs_strndup0(const char *s, size_t n) {
    char *p;
    if (!s) return NULL;
    p = (char *)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

static size_t cs_input_len(const SQLCHAR *s, SQLINTEGER n) {
    if (!s) return 0;
    return n == SQL_NTS ? strlen((const char *)s) : (n < 0 ? 0 : (size_t)n);
}

static size_t cs_winput_len(const SQLWCHAR *s, SQLINTEGER n) {
    size_t len = 0;
    if (!s) return 0;
    if (n != SQL_NTS) return n < 0 ? 0 : (size_t)n;
    while (s[len]) ++len;
    return len;
}

static int cs_ascii_equal(const char *a, const char *b) {
    unsigned char ca, cb;
    if (!a || !b) return 0;
    while (*a && *b) {
        ca = (unsigned char)tolower((unsigned char)*a++);
        cb = (unsigned char)tolower((unsigned char)*b++);
        if (ca != cb) return 0;
    }
    return *a == '\0' && *b == '\0';
}

void cs_diag_clear(cs_handle *h) {
    if (!h) return;
    h->diag_count = 0;
    h->diag_next = 0;
    h->last_return = SQL_SUCCESS;
    memset(h->diag, 0, sizeof(h->diag));
}

SQLRETURN cs_diag_add(cs_handle *h, const char *state, SQLINTEGER native,
                      const char *format, ...) {
    va_list args;
    cs_diag_record *r;
    if (!h) return SQL_ERROR;
    h->last_return = SQL_ERROR;
    if (h->diag_count >= CSODBC_MAX_DIAG) return SQL_ERROR;
    r = &h->diag[h->diag_count++];
    memcpy(r->state, state ? state : "HY000", 5);
    r->state[5] = '\0';
    r->native = native;
    va_start(args, format);
    vsnprintf(r->message, sizeof(r->message), format ? format : "", args);
    va_end(args);
    r->message[sizeof(r->message) - 1] = '\0';
    return SQL_ERROR;
}

/*
 * Records a warning (for example 01S02 "option value changed") and returns
 * SQL_SUCCESS_WITH_INFO. cs_diag_add always reports SQL_ERROR, which turned
 * every substituted attribute value into a hard failure.
 */
SQLRETURN cs_diag_warn(cs_handle *h, const char *state, const char *format, ...) {
    va_list args;
    cs_diag_record *r;
    if (!h) return SQL_SUCCESS_WITH_INFO;
    if (h->diag_count >= CSODBC_MAX_DIAG) return SQL_SUCCESS_WITH_INFO;
    r = &h->diag[h->diag_count++];
    memcpy(r->state, state ? state : "01000", 5);
    r->state[5] = '\0';
    r->native = 0;
    va_start(args, format);
    vsnprintf(r->message, sizeof(r->message), format ? format : "", args);
    va_end(args);
    r->message[sizeof(r->message) - 1] = '\0';
    h->last_return = SQL_SUCCESS_WITH_INFO;
    return SQL_SUCCESS_WITH_INFO;
}

int cs_valid_handle(SQLHANDLE handle, SQLSMALLINT type) {
    cs_handle *h = (cs_handle *)handle;
    return h && h->magic == CSODBC_MAGIC && h->type == type;
}

char *cs_utf16_to_utf8(const SQLWCHAR *input, SQLINTEGER length) {
    size_t i, n, cap, pos = 0;
    char *out;
    if (!input) return cs_strndup0("", 0);
    n = cs_winput_len(input, length);
    cap = n * 4 + 1;
    out = (char *)malloc(cap);
    if (!out) return NULL;
    for (i = 0; i < n; ++i) {
        uint32_t cp = input[i];
        if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < n &&
            input[i + 1] >= 0xdc00 && input[i + 1] <= 0xdfff) {
            cp = 0x10000 + ((cp - 0xd800) << 10) + (input[++i] - 0xdc00);
        }
        if (cp < 0x80) out[pos++] = (char)cp;
        else if (cp < 0x800) {
            out[pos++] = (char)(0xc0 | (cp >> 6));
            out[pos++] = (char)(0x80 | (cp & 0x3f));
        } else if (cp < 0x10000) {
            out[pos++] = (char)(0xe0 | (cp >> 12));
            out[pos++] = (char)(0x80 | ((cp >> 6) & 0x3f));
            out[pos++] = (char)(0x80 | (cp & 0x3f));
        } else {
            out[pos++] = (char)(0xf0 | (cp >> 18));
            out[pos++] = (char)(0x80 | ((cp >> 12) & 0x3f));
            out[pos++] = (char)(0x80 | ((cp >> 6) & 0x3f));
            out[pos++] = (char)(0x80 | (cp & 0x3f));
        }
    }
    out[pos] = '\0';
    return out;
}

/*
 * SQL_C_CHAR is defined as the application's character set, which on Windows
 * means the process ANSI code page. CubeSQL speaks UTF-8, so the ANSI data
 * paths convert in both directions. Connections can opt out with CHARSET=UTF8
 * when the application really does want raw UTF-8 in SQL_C_CHAR buffers.
 *
 * Off Windows there is no ANSI code page: the test build passes UTF-8 through,
 * which is also what unixODBC applications expect.
 */
char *cs_utf8_to_ansi(const char *utf8, size_t len, size_t *out_len) {
#ifdef _WIN32
    int wide_len, ansi_len;
    WCHAR *wide;
    char *ansi;
    if (!utf8) return NULL;
    wide_len = MultiByteToWideChar(CP_UTF8, 0, utf8, (int)len, NULL, 0);
    if (wide_len < 0) return NULL;
    wide = (WCHAR *)malloc(((size_t)wide_len + 1) * sizeof(WCHAR));
    if (!wide) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, utf8, (int)len, wide, wide_len);
    ansi_len = WideCharToMultiByte(CP_ACP, 0, wide, wide_len, NULL, 0, NULL, NULL);
    if (ansi_len < 0) { free(wide); return NULL; }
    ansi = (char *)malloc((size_t)ansi_len + 1);
    if (!ansi) { free(wide); return NULL; }
    WideCharToMultiByte(CP_ACP, 0, wide, wide_len, ansi, ansi_len, NULL, NULL);
    ansi[ansi_len] = '\0';
    free(wide);
    if (out_len) *out_len = (size_t)ansi_len;
    return ansi;
#else
    char *copy = cs_strndup0(utf8, len);
    if (copy && out_len) *out_len = len;
    return copy;
#endif
}

char *cs_ansi_to_utf8(const char *ansi, size_t len, size_t *out_len) {
#ifdef _WIN32
    int wide_len, utf8_len;
    WCHAR *wide;
    char *utf8;
    if (!ansi) return NULL;
    wide_len = MultiByteToWideChar(CP_ACP, 0, ansi, (int)len, NULL, 0);
    if (wide_len < 0) return NULL;
    wide = (WCHAR *)malloc(((size_t)wide_len + 1) * sizeof(WCHAR));
    if (!wide) return NULL;
    MultiByteToWideChar(CP_ACP, 0, ansi, (int)len, wide, wide_len);
    utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide, wide_len, NULL, 0, NULL, NULL);
    if (utf8_len < 0) { free(wide); return NULL; }
    utf8 = (char *)malloc((size_t)utf8_len + 1);
    if (!utf8) { free(wide); return NULL; }
    WideCharToMultiByte(CP_UTF8, 0, wide, wide_len, utf8, utf8_len, NULL, NULL);
    utf8[utf8_len] = '\0';
    free(wide);
    if (out_len) *out_len = (size_t)utf8_len;
    return utf8;
#else
    char *copy = cs_strndup0(ansi, len);
    if (copy && out_len) *out_len = len;
    return copy;
#endif
}

static size_t cs_utf8_to_utf16_buf(const char *in, SQLWCHAR *out, size_t cap) {
    const unsigned char *p = (const unsigned char *)(in ? in : "");
    size_t n = 0;
    while (*p) {
        uint32_t cp;
        if (*p < 0x80) cp = *p++;
        else if ((*p & 0xe0) == 0xc0 && p[1]) {
            cp = ((uint32_t)(p[0] & 0x1f) << 6) | (p[1] & 0x3f); p += 2;
        } else if ((*p & 0xf0) == 0xe0 && p[1] && p[2]) {
            cp = ((uint32_t)(p[0] & 0x0f) << 12) | ((uint32_t)(p[1] & 0x3f) << 6) | (p[2] & 0x3f); p += 3;
        } else if ((*p & 0xf8) == 0xf0 && p[1] && p[2] && p[3]) {
            cp = ((uint32_t)(p[0] & 7) << 18) | ((uint32_t)(p[1] & 0x3f) << 12) |
                 ((uint32_t)(p[2] & 0x3f) << 6) | (p[3] & 0x3f); p += 4;
        } else { cp = 0xfffd; ++p; }
        if (cp <= 0xffff) {
            if (out && n + 1 < cap) out[n] = (SQLWCHAR)cp;
            ++n;
        } else {
            cp -= 0x10000;
            if (out && n + 2 < cap) {
                out[n] = (SQLWCHAR)(0xd800 + (cp >> 10));
                out[n + 1] = (SQLWCHAR)(0xdc00 + (cp & 0x3ff));
            }
            n += 2;
        }
    }
    if (out && cap) out[n < cap ? n : cap - 1] = 0;
    return n;
}

/*
 * Copies a UTF-8 string to an ANSI application buffer, converting when the
 * connection uses the ANSI code page. Used for the names and messages that can
 * legitimately contain non-ASCII text.
 */
SQLRETURN cs_copy_ansi(SQLCHAR *out, SQLLEN capacity, SQLLEN *length,
                       const char *value, cs_handle *diag, int ansi_charset) {
    SQLRETURN rc;
    char *converted;
    if (!ansi_charset) return cs_copy_utf8(out, capacity, length, value, diag);
    converted = cs_utf8_to_ansi(value ? value : "", strlen(value ? value : ""), NULL);
    if (!converted) return cs_copy_utf8(out, capacity, length, value, diag);
    rc = cs_copy_utf8(out, capacity, length, converted, diag);
    free(converted);
    return rc;
}

SQLRETURN cs_copy_utf8(SQLCHAR *out, SQLLEN capacity, SQLLEN *length,
                       const char *value, cs_handle *diag) {
    size_t n = strlen(value ? value : "");
    if (length) *length = (SQLLEN)n;
    if (!out || capacity <= 0) return SQL_SUCCESS;
    if ((size_t)capacity <= n) {
        memcpy(out, value, (size_t)capacity - 1);
        out[capacity - 1] = 0;
        if (diag) {
            cs_diag_add(diag, "01004", 0, "String data, right truncated");
            diag->last_return = SQL_SUCCESS_WITH_INFO;
        }
        return SQL_SUCCESS_WITH_INFO;
    }
    memcpy(out, value, n + 1);
    return SQL_SUCCESS;
}

SQLRETURN cs_copy_utf16(SQLWCHAR *out, SQLLEN capacity, SQLLEN *length,
                        const char *value, cs_handle *diag) {
    size_t n = cs_utf8_to_utf16_buf(value, NULL, 0);
    if (length) *length = (SQLLEN)n;
    if (!out || capacity <= 0) return SQL_SUCCESS;
    cs_utf8_to_utf16_buf(value, out, (size_t)capacity);
    if ((size_t)capacity <= n) {
        if (diag) {
            cs_diag_add(diag, "01004", 0, "String data, right truncated");
            diag->last_return = SQL_SUCCESS_WITH_INFO;
        }
        return SQL_SUCCESS_WITH_INFO;
    }
    return SQL_SUCCESS;
}

static cs_handle *cs_get_handle(SQLSMALLINT type, SQLHANDLE handle) {
    return cs_valid_handle(handle, type) ? (cs_handle *)handle : NULL;
}

static void cs_stmt_close(cs_stmt *stmt) {
    SQLUSMALLINT i;
    if (stmt->cursor) cubesql_cursor_free(stmt->cursor);
    stmt->cursor = NULL;
    stmt->executed = 0;
    /* i tipi risolti dal catalogo valgono solo per il result set che si chiude */
    stmt->types_resolved = 0;
    stmt->current_row = 0;
    stmt->row_count = 0;
    stmt->rowset_start = 0;
    stmt->rowset_count = 0;
    memset(stmt->getdata_offset, 0, sizeof(stmt->getdata_offset));
    for (i = 0; i < stmt->num_params; ++i) {
        free(stmt->params[i].at_exec);
        stmt->params[i].at_exec = NULL;
        stmt->params[i].at_exec_len = 0;
        stmt->params[i].at_exec_cap = 0;
    }
    stmt->at_exec_param = 0;
    stmt->need_data_active = 0;
}

static void cs_unlink_stmt(cs_stmt *stmt) {
    cs_stmt **p = &stmt->dbc->statements;
    while (*p && *p != stmt) p = &(*p)->next;
    if (*p) *p = stmt->next;
}

static void cs_unlink_dbc(cs_dbc *dbc) {
    cs_dbc **p = &dbc->env->connections;
    while (*p && *p != dbc) p = &(*p)->next;
    if (*p) *p = dbc->next;
}

static void cs_stmt_defaults(cs_stmt *stmt) {
    stmt->row_array_size = 1;
    stmt->paramset_size = 1;
    stmt->row_bind_type = SQL_BIND_BY_COLUMN;
    stmt->param_bind_type = SQL_BIND_BY_COLUMN;
    stmt->cursor_type = SQL_CURSOR_FORWARD_ONLY;
    stmt->concurrency = SQL_CONCUR_READ_ONLY;
    stmt->retrieve_data = SQL_RD_ON;
    stmt->use_bookmarks = SQL_UB_OFF;
    stmt->noscan = SQL_NOSCAN_OFF;
    stmt->async_enable = SQL_ASYNC_ENABLE_OFF;
    stmt->cursor_scrollable = SQL_NONSCROLLABLE;
    stmt->cursor_sensitivity = SQL_INSENSITIVE;
    stmt->simulate_cursor = SQL_SC_UNIQUE;
    stmt->metadata_id = SQL_FALSE;
}

/*
 * Hand-written rather than generated: allocation and destruction have to take
 * the parent's lock, and freeing a connection or environment destroys the very
 * mutex a generated wrapper would still be holding.
 */
CSODBC_EXPORT SQLRETURN SQL_API SQLAllocHandle(SQLSMALLINT type, SQLHANDLE input,
                                               SQLHANDLE *output) {
    if (!output) return SQL_ERROR;
    *output = SQL_NULL_HANDLE;
    if (type == SQL_HANDLE_ENV) {
        cs_env *env;
        if (input != SQL_NULL_HANDLE) return SQL_INVALID_HANDLE;
        env = (cs_env *)calloc(1, sizeof(*env));
        if (!env) return SQL_ERROR;
        env->h.magic = CSODBC_MAGIC; env->h.type = type;
        env->odbc_version = SQL_OV_ODBC3; env->output_nts = SQL_TRUE;
        env->connection_pooling = SQL_CP_OFF; env->cp_match = SQL_CP_STRICT_MATCH;
        cs_mutex_init(&env->lock);
        *output = (SQLHANDLE)env;
    } else if (type == SQL_HANDLE_DBC) {
        cs_env *env = (cs_env *)input;
        cs_dbc *dbc;
        if (!cs_valid_handle(input, SQL_HANDLE_ENV)) return SQL_INVALID_HANDLE;
        cs_mutex_lock(&env->lock);
        cs_diag_clear(&env->h);
        dbc = (cs_dbc *)calloc(1, sizeof(*dbc));
        if (!dbc) {
            cs_mutex_unlock(&env->lock);
            return cs_diag_add(&env->h, "HY001", 0, "Memory allocation error");
        }
        dbc->h.magic = CSODBC_MAGIC; dbc->h.type = type; dbc->env = env;
        dbc->autocommit = SQL_AUTOCOMMIT_ON; dbc->access_mode = SQL_MODE_READ_WRITE;
        dbc->txn_isolation = SQL_TXN_SERIALIZABLE; dbc->login_timeout = CUBESQL_DEFAULT_TIMEOUT;
        dbc->metadata_id = SQL_FALSE; dbc->packet_size = 0;
        dbc->odbc_cursors = SQL_CUR_USE_DRIVER; dbc->async_enable = SQL_ASYNC_ENABLE_OFF;
        dbc->auto_ipd = SQL_FALSE;
        strcpy(dbc->host, "localhost"); strcpy(dbc->port, "4430"); strcpy(dbc->encryption, "AES256");
        cs_mutex_init(&dbc->lock);
        dbc->next = env->connections; env->connections = dbc;
        cs_mutex_unlock(&env->lock);
        *output = (SQLHANDLE)dbc;
    } else if (type == SQL_HANDLE_STMT) {
        cs_dbc *dbc = (cs_dbc *)input;
        cs_stmt *stmt;
        if (!cs_valid_handle(input, SQL_HANDLE_DBC)) return SQL_INVALID_HANDLE;
        cs_mutex_lock(&dbc->lock);
        cs_diag_clear(&dbc->h);
        if (!dbc->connected) {
            cs_mutex_unlock(&dbc->lock);
            return cs_diag_add(&dbc->h, "08003", 0, "Connection is not open");
        }
        stmt = (cs_stmt *)calloc(1, sizeof(*stmt));
        if (!stmt) {
            cs_mutex_unlock(&dbc->lock);
            return cs_diag_add(&dbc->h, "HY001", 0, "Memory allocation error");
        }
        stmt->h.magic = CSODBC_MAGIC; stmt->h.type = type; stmt->dbc = dbc;
        cs_stmt_defaults(stmt);
        stmt->next = dbc->statements; dbc->statements = stmt;
        cs_mutex_unlock(&dbc->lock);
        *output = (SQLHANDLE)stmt;
    } else if (type == SQL_HANDLE_DESC) {
        if (!cs_valid_handle(input, SQL_HANDLE_DBC)) return SQL_INVALID_HANDLE;
        return cs_diag_add((cs_handle *)input, "HYC00", 0, "Explicit descriptors are not implemented");
    } else return SQL_ERROR;
    return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLFreeHandle(SQLSMALLINT type, SQLHANDLE handle) {
    cs_handle *h = cs_get_handle(type, handle);
    if (!h) return SQL_INVALID_HANDLE;
    if (type == SQL_HANDLE_STMT) {
        cs_stmt *stmt = (cs_stmt *)handle;
        cs_dbc *dbc = stmt->dbc;
        cs_mutex_lock(&dbc->lock);
        cs_diag_clear(h);
        cs_unlink_stmt(stmt); cs_stmt_close(stmt); free(stmt->sql);
        stmt->h.magic = 0; free(stmt);
        cs_mutex_unlock(&dbc->lock);
    } else if (type == SQL_HANDLE_DBC) {
        cs_dbc *dbc = (cs_dbc *)handle;
        cs_env *env = dbc->env;
        cs_mutex_lock(&env->lock);
        cs_mutex_lock(&dbc->lock);
        cs_diag_clear(h);
        if (dbc->connected) {
            cs_mutex_unlock(&dbc->lock);
            cs_mutex_unlock(&env->lock);
            return cs_diag_add(h, "HY010", 0, "Disconnect before freeing the connection");
        }
        /*
         * The spec lets an application free a connection that still owns
         * statements; SQLDisconnect already dropped them, but a connection that
         * was never opened can still have none. Free whatever is left.
         */
        while (dbc->statements) {
            cs_stmt *stmt = dbc->statements;
            dbc->statements = stmt->next;
            cs_stmt_close(stmt); free(stmt->sql); stmt->h.magic = 0; free(stmt);
        }
        cs_unlink_dbc(dbc);
        dbc->h.magic = 0;
        cs_mutex_unlock(&dbc->lock);
        cs_mutex_destroy(&dbc->lock);
        free(dbc);
        cs_mutex_unlock(&env->lock);
    } else if (type == SQL_HANDLE_ENV) {
        cs_env *env = (cs_env *)handle;
        cs_mutex_lock(&env->lock);
        cs_diag_clear(h);
        if (env->connections) {
            cs_mutex_unlock(&env->lock);
            return cs_diag_add(h, "HY010", 0, "Connections must be freed before the environment");
        }
        env->h.magic = 0;
        cs_mutex_unlock(&env->lock);
        cs_mutex_destroy(&env->lock);
        free(env);
    } else return SQL_ERROR;
    return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLAllocEnv(SQLHENV *env) {
    return SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, (SQLHANDLE *)env);
}
CSODBC_EXPORT SQLRETURN SQL_API SQLAllocConnect(SQLHENV env, SQLHDBC *dbc) {
    return SQLAllocHandle(SQL_HANDLE_DBC, env, (SQLHANDLE *)dbc);
}
CSODBC_EXPORT SQLRETURN SQL_API SQLAllocStmt(SQLHDBC dbc, SQLHSTMT *stmt) {
    return SQLAllocHandle(SQL_HANDLE_STMT, dbc, (SQLHANDLE *)stmt);
}
CSODBC_EXPORT SQLRETURN SQL_API SQLFreeEnv(SQLHENV env) { return SQLFreeHandle(SQL_HANDLE_ENV, env); }
CSODBC_EXPORT SQLRETURN SQL_API SQLFreeConnect(SQLHDBC dbc) { return SQLFreeHandle(SQL_HANDLE_DBC, dbc); }

static cs_handle *cs_diag_handle(SQLSMALLINT type, SQLHANDLE handle) {
    return cs_get_handle(type, handle);
}

static SQLRETURN SQL_API cs_i_SQLGetDiagRec(SQLSMALLINT type, SQLHANDLE handle,
    SQLSMALLINT record, SQLCHAR *state, SQLINTEGER *native, SQLCHAR *message,
    SQLSMALLINT capacity, SQLSMALLINT *length) {
    cs_handle *h = cs_diag_handle(type, handle);
    cs_diag_record *r;
    SQLLEN n = 0;
    SQLRETURN rc;
    if (!h) return SQL_INVALID_HANDLE;
    if (record < 1 || record > h->diag_count) return SQL_NO_DATA;
    r = &h->diag[record - 1];
    if (state) memcpy(state, r->state, 6);
    if (native) *native = r->native;
    rc = cs_copy_utf8(message, capacity, &n, r->message, NULL);
    if (length) *length = (SQLSMALLINT)n;
    return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetDiagRec(SQLSMALLINT type, SQLHANDLE handle,
    SQLSMALLINT record, SQLCHAR *state, SQLINTEGER *native, SQLCHAR *message,
    SQLSMALLINT capacity, SQLSMALLINT *length) {
    cs_mutex *cs__m = cs_handle_lock(type, handle);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetDiagRec(type, handle, record, state, native, message, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetDiagRecW(SQLSMALLINT type, SQLHANDLE handle,
    SQLSMALLINT record, SQLWCHAR *state, SQLINTEGER *native, SQLWCHAR *message,
    SQLSMALLINT capacity, SQLSMALLINT *length) {
    cs_handle *h = cs_diag_handle(type, handle);
    cs_diag_record *r;
    SQLLEN n = 0;
    SQLRETURN rc;
    if (!h) return SQL_INVALID_HANDLE;
    if (record < 1 || record > h->diag_count) return SQL_NO_DATA;
    r = &h->diag[record - 1];
    if (state) cs_utf8_to_utf16_buf(r->state, state, 6);
    if (native) *native = r->native;
    rc = cs_copy_utf16(message, capacity, &n, r->message, NULL);
    if (length) *length = (SQLSMALLINT)n;
    return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetDiagRecW(SQLSMALLINT type, SQLHANDLE handle,
    SQLSMALLINT record, SQLWCHAR *state, SQLINTEGER *native, SQLWCHAR *message,
    SQLSMALLINT capacity, SQLSMALLINT *length) {
    cs_mutex *cs__m = cs_handle_lock(type, handle);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetDiagRecW(type, handle, record, state, native, message, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetDiagField(SQLSMALLINT type, SQLHANDLE handle,
    SQLSMALLINT record, SQLSMALLINT id, SQLPOINTER info, SQLSMALLINT capacity,
    SQLSMALLINT *length) {
    cs_handle *h = cs_diag_handle(type, handle);
    cs_diag_record *r = NULL;
    SQLLEN n = 0;
    if (!h) return SQL_INVALID_HANDLE;
    if (record > 0) {
        if (record > h->diag_count) return SQL_NO_DATA;
        r = &h->diag[record - 1];
    }
    if (id == SQL_DIAG_NUMBER) { if (info) *(SQLINTEGER *)info = h->diag_count; return SQL_SUCCESS; }
    if (!r) return SQL_ERROR;
    if (id == SQL_DIAG_NATIVE) { if (info) *(SQLINTEGER *)info = r->native; return SQL_SUCCESS; }
    if (id == SQL_DIAG_SQLSTATE) { SQLRETURN rc=cs_copy_utf8((SQLCHAR *)info,capacity,&n,r->state,NULL);if(length)*length=(SQLSMALLINT)n;return rc; }
    if (id == SQL_DIAG_MESSAGE_TEXT) { SQLRETURN rc=cs_copy_utf8((SQLCHAR *)info,capacity,&n,r->message,NULL);if(length)*length=(SQLSMALLINT)n;return rc; }
    if (id == SQL_DIAG_CLASS_ORIGIN || id == SQL_DIAG_SUBCLASS_ORIGIN) { SQLRETURN rc=cs_copy_utf8((SQLCHAR *)info,capacity,&n,"ISO 9075",NULL);if(length)*length=(SQLSMALLINT)n;return rc; }
    if (id == SQL_DIAG_CONNECTION_NAME || id == SQL_DIAG_SERVER_NAME) { SQLRETURN rc=cs_copy_utf8((SQLCHAR *)info,capacity,&n,"",NULL);if(length)*length=(SQLSMALLINT)n;return rc; }
    if (length) *length = (SQLSMALLINT)n;
    return SQL_ERROR;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetDiagField(SQLSMALLINT type, SQLHANDLE handle,
    SQLSMALLINT record, SQLSMALLINT id, SQLPOINTER info, SQLSMALLINT capacity,
    SQLSMALLINT *length) {
    cs_mutex *cs__m = cs_handle_lock(type, handle);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetDiagField(type, handle, record, id, info, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

/*
 * SQLError walks the diagnostic records one per call and reports SQL_NO_DATA
 * once they are exhausted. Every caller - the Driver Manager included - loops
 * on it until that happens.
 *
 * This used to hand back record 1 on every call, so the loop never ended: the
 * caller kept receiving SQL_SUCCESS and the same message for ever, appending it
 * to its own buffer until memory ran out. On a machine with little RAM that
 * took the whole system down, and it fired on ANY failing statement, which is
 * why "SELECT 1;" without a current database was enough to hang a consumer.
 *
 * SQLError e SQLErrorW hanno due corpi distinti: la logica del cursore sta
 * qui in un punto solo, perche' e' esattamente tenendo due copie a mano che
 * questo difetto e' nato, ed e' sopravvissuto alla prima correzione proprio
 * perche' ne era stata sistemata una sola.
 *
 * Sceglie l'handle secondo le regole di SQLError e avanza di un record.
 * Restituisce il numero del record, 0 quando sono esauriti, -1 se l'handle
 * non e' valido.
 */
static SQLSMALLINT cs_diag_take_next(SQLHENV env, SQLHDBC dbc, SQLHSTMT stmt,
                                     SQLSMALLINT *out_type, SQLHANDLE *out_handle) {
    SQLSMALLINT type; SQLHANDLE handle; cs_handle *h; SQLSMALLINT record = 0;
    cs_mutex *cs__m;

    if (stmt) { type = SQL_HANDLE_STMT; handle = stmt; }
    else if (dbc) { type = SQL_HANDLE_DBC; handle = dbc; }
    else if (env) { type = SQL_HANDLE_ENV; handle = env; }
    else return -1;

    cs__m = cs_handle_lock(type, handle);
    if (cs__m) cs_mutex_lock(cs__m);
    h = cs_diag_handle(type, handle);
    if (!h) { if (cs__m) cs_mutex_unlock(cs__m); return -1; }
    if (h->diag_next < h->diag_count) {
        record = (SQLSMALLINT)(h->diag_next + 1);
        h->diag_next++;
    }
    if (cs__m) cs_mutex_unlock(cs__m);

    *out_type = type;
    *out_handle = handle;
    return record;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLError(SQLHENV env, SQLHDBC dbc, SQLHSTMT stmt,
    SQLCHAR *state, SQLINTEGER *native, SQLCHAR *message, SQLSMALLINT capacity,
    SQLSMALLINT *length) {
    SQLSMALLINT type = 0; SQLHANDLE handle = NULL;
    SQLSMALLINT record = cs_diag_take_next(env, dbc, stmt, &type, &handle);
    if (record < 0) return SQL_INVALID_HANDLE;
    if (record == 0) return SQL_NO_DATA;
    return SQLGetDiagRec(type, handle, record, state, native, message, capacity, length);
}

void cs_option_set(char *dst, size_t cap, const char *value) {
    size_t n;
    if (!dst || !cap || !value) return;
    n = strlen(value); if (n >= cap) n = cap - 1;
    memcpy(dst, value, n); dst[n] = '\0';
}

static void cs_option(cs_conn_options *o, const char *key, const char *value) {
    if (cs_ascii_equal(key, "DSN")) { cs_option_set(o->dsn, sizeof(o->dsn), value); o->seen |= CS_OPT_SEEN_DSN; }
    else if (cs_ascii_equal(key, "SERVER") || cs_ascii_equal(key, "HOST")) cs_option_set(o->host, sizeof(o->host), value);
    else if (cs_ascii_equal(key, "PORT")) cs_option_set(o->port, sizeof(o->port), value);
    else if (cs_ascii_equal(key, "UID") || cs_ascii_equal(key, "USER") || cs_ascii_equal(key, "USERNAME")) { cs_option_set(o->user, sizeof(o->user), value); o->seen |= CS_OPT_SEEN_UID; }
    else if (cs_ascii_equal(key, "PWD") || cs_ascii_equal(key, "PASSWORD")) { cs_option_set(o->password, sizeof(o->password), value); o->seen |= CS_OPT_SEEN_PWD; }
    else if (cs_ascii_equal(key, "DATABASE") || cs_ascii_equal(key, "DB")) cs_option_set(o->database, sizeof(o->database), value);
    else if (cs_ascii_equal(key, "ENCRYPTION") || cs_ascii_equal(key, "ENC")) cs_option_set(o->encryption, sizeof(o->encryption), value);
    else if (cs_ascii_equal(key, "TIMEOUT") || cs_ascii_equal(key, "LOGINTIMEOUT")) cs_option_set(o->timeout, sizeof(o->timeout), value);
    else if (cs_ascii_equal(key, "CHARSET")) cs_option_set(o->charset, sizeof(o->charset), value);
}

int cs_parse_connection_string(cs_conn_options *o, const char *input) {
    const char *p = input ? input : "";
    while (*p) {
        const char *key_start, *key_end, *value_start;
        char key[64], value[1024];
        size_t kn = 0, vn = 0;
        while (*p == ';' || isspace((unsigned char)*p)) ++p;
        if (!*p) break;
        key_start = p;
        while (*p && *p != '=' && *p != ';') ++p;
        if (*p != '=') return 0;
        key_end = p++;
        while (key_start < key_end && isspace((unsigned char)*key_start)) ++key_start;
        while (key_end > key_start && isspace((unsigned char)key_end[-1])) --key_end;
        kn = (size_t)(key_end - key_start);
        if (!kn || kn >= sizeof(key)) return 0;
        memcpy(key, key_start, kn); key[kn] = '\0';
        while (isspace((unsigned char)*p)) ++p;
        if (*p == '{') {
            ++p;
            while (*p) {
                if (*p == '}') {
                    if (p[1] == '}') { if (vn + 1 < sizeof(value)) value[vn++] = '}'; p += 2; continue; }
                    ++p; break;
                }
                if (vn + 1 < sizeof(value)) value[vn++] = *p;
                ++p;
            }
            while (isspace((unsigned char)*p)) ++p;
            if (*p && *p != ';') return 0;
        } else {
            value_start = p;
            while (*p && *p != ';') ++p;
            while (p > value_start && isspace((unsigned char)p[-1])) --p;
            vn = (size_t)(p - value_start);
            if (vn >= sizeof(value)) vn = sizeof(value) - 1;
            memcpy(value, value_start, vn);
        }
        value[vn] = '\0';
        cs_option(o, key, value);
        while (*p && *p != ';') ++p;
        if (*p == ';') ++p;
    }
    return 1;
}

static void cs_read_dsn(cs_conn_options *o) {
#ifdef _WIN32
    char buffer[1024];
#define CS_READ_DSN(name, member) do { \
    SQLGetPrivateProfileString(o->dsn, name, "", buffer, (int)sizeof(buffer), "ODBC.INI"); \
    if (!o->member[0] && buffer[0]) cs_option_set(o->member, sizeof(o->member), buffer); \
} while (0)
    if (!o->dsn[0]) return;
    CS_READ_DSN("Server", host);
    CS_READ_DSN("Port", port);
    CS_READ_DSN("UID", user);
    CS_READ_DSN("Database", database);
    CS_READ_DSN("Encryption", encryption);
    CS_READ_DSN("Timeout", timeout);
    CS_READ_DSN("Charset", charset);
#undef CS_READ_DSN
#else
    (void)o;
#endif
}

int cs_encryption_value(const char *value) {
    if (!value || !*value || cs_ascii_equal(value, "AES256")) return CUBESQL_ENCRYPTION_AES256;
    if (cs_ascii_equal(value, "NONE") || cs_ascii_equal(value, "0")) return CUBESQL_ENCRYPTION_NONE;
    if (cs_ascii_equal(value, "AES128")) return CUBESQL_ENCRYPTION_AES128;
    if (cs_ascii_equal(value, "AES192")) return CUBESQL_ENCRYPTION_AES192;
    if (cs_ascii_equal(value, "SSL") || cs_ascii_equal(value, "TLS")) return CUBESQL_ENCRYPTION_SSL;
    if (cs_ascii_equal(value, "SSL+AES128") || cs_ascii_equal(value, "TLS+AES128")) return CUBESQL_ENCRYPTION_SSL_AES128;
    if (cs_ascii_equal(value, "SSL+AES192") || cs_ascii_equal(value, "TLS+AES192")) return CUBESQL_ENCRYPTION_SSL_AES192;
    if (cs_ascii_equal(value, "SSL+AES256") || cs_ascii_equal(value, "TLS+AES256")) return CUBESQL_ENCRYPTION_SSL_AES256;
    return -1;
}

/* Server reply code for "the maximum number of allowed connections". */
#define CS_SERVER_MAX_CONNECTIONS 7020

static void cs_map_sdk_error(cs_handle *h, csqldb *db, int code, const char *operation) {
    const char *state = "HY000";
    const char *message = db ? cubesql_errmsg(db) : NULL;
    /*
     * A connection-limited licence rejects the second concurrent socket. The
     * usual cause is Driver Manager connection pooling: SQLDisconnect returns
     * the socket to the pool instead of closing it, so the next connect opens
     * an extra one. Say so, because the bare server message sends people
     * hunting for a leak in their own code.
     */
    if (code == CS_SERVER_MAX_CONNECTIONS ||
        (message && strstr(message, "maximum number of allowed connections"))) {
        cs_diag_add(h, "08004", code,
            "The CubeSQL server refused the connection: the licensed number of "
            "concurrent connections is already in use. If the application "
            "appears to use a single connection, disable ODBC connection "
            "pooling for this driver: a pooled connection stays open on the "
            "server after SQLDisconnect and still counts against the limit.");
        return;
    }
    if (code == CUBESQL_MEMORY_ERROR) state = "HY001";
    else if (code == CUBESQL_PARAMETER_ERROR) state = "HY009";
    else if (code == CUBESQL_SSL_ERROR || code == CUBESQL_SSL_CERT_ERROR || code == CUBESQL_SSL_DISABLED_ERROR) state = "08001";
    else if (operation && cs_ascii_equal(operation, "connect")) state = "08001";
    else if (message && (strstr(message, "syntax") || strstr(message, "Syntax"))) state = "42000";
    else if (message && strstr(message, "locked")) state = "HYT00";
    else if (message && strstr(message, "constraint")) state = "23000";
    cs_diag_add(h, state, code, "%s%s%s", operation ? operation : "CubeSQL error",
                message && *message ? ": " : "", message && *message ? message : "operation failed");
}

void cs_conn_apply_defaults(cs_conn_options *o) {
    if (!o->host[0]) strcpy(o->host, "localhost");
    if (!o->port[0]) strcpy(o->port, "4430");
    if (!o->encryption[0]) strcpy(o->encryption, "AES256");
    if (!o->timeout[0]) strcpy(o->timeout, "12");
}

static SQLRETURN cs_connect_options(cs_dbc *dbc, cs_conn_options *o) {
    int port, timeout, encryption, rc;
    cs_diag_clear(&dbc->h);
    if (dbc->connected) return cs_diag_add(&dbc->h, "08002", 0, "Connection is already open");
    cs_read_dsn(o);
    if (!o->timeout[0]) snprintf(o->timeout, sizeof(o->timeout), "%lu", (unsigned long)dbc->login_timeout);
    cs_conn_apply_defaults(o);
    if (!o->user[0]) return cs_diag_add(&dbc->h, "28000", 0, "UID is required");
    port = atoi(o->port); timeout = atoi(o->timeout); encryption = cs_encryption_value(o->encryption);
    if (port < 1 || port > 65535) return cs_diag_add(&dbc->h, "HY024", 0, "Invalid port number");
    if (timeout < 0) return cs_diag_add(&dbc->h, "HY024", 0, "Invalid timeout");
    if (encryption < 0) return cs_diag_add(&dbc->h, "HY024", 0, "Unsupported encryption value '%s'", o->encryption);
    rc = cubesql_connect(&dbc->db, o->host, port, o->user, o->password, timeout, encryption);
    if (rc != CUBESQL_NOERR) { cs_map_sdk_error(&dbc->h, dbc->db, rc, "connect"); return SQL_ERROR; }
    if (o->database[0]) {
        rc = cubesql_set_database(dbc->db, o->database);
        if (rc != CUBESQL_NOERR) {
            cs_map_sdk_error(&dbc->h, dbc->db, rc, "set database");
            cubesql_disconnect(dbc->db, kTRUE); dbc->db = NULL; return SQL_ERROR;
        }
    }
    dbc->connected = 1;
    dbc->dead = 0;
    dbc->in_transaction = 0;
    strcpy(dbc->dbms_version,"00.00.0000");
    {
        csqlc *info=cubesql_select(dbc->db,"SHOW INFO;",kFALSE);int row,rows;
        if(info){rows=cubesql_cursor_numrows(info);for(row=1;row<=rows;row++){char *key=cubesql_cursor_cstring(info,row,1);if(key&&cs_ascii_equal(key,"server_version")){char *v=cubesql_cursor_cstring(info,row,2);int a=0,b=0,c=0;if(v&&sscanf(v,"%d.%d.%d",&a,&b,&c)>=2)snprintf(dbc->dbms_version,sizeof(dbc->dbms_version),"%02d.%02d.%04d",a,b,c);free(v);free(key);break;}free(key);}cubesql_cursor_free(info);}else cubesql_clear_errors(dbc->db);
    }
    cs_option_set(dbc->dsn, sizeof(dbc->dsn), o->dsn);
    cs_option_set(dbc->host, sizeof(dbc->host), o->host);
    cs_option_set(dbc->port, sizeof(dbc->port), o->port);
    cs_option_set(dbc->user, sizeof(dbc->user), o->user);
    cs_option_set(dbc->password, sizeof(dbc->password), o->password);
    cs_option_set(dbc->database, sizeof(dbc->database), o->database);
    cs_option_set(dbc->encryption, sizeof(dbc->encryption), o->encryption);
    /*
     * SQL_C_CHAR defaults to the ANSI code page on Windows, which is what ODBC
     * applications expect, and to raw UTF-8 elsewhere. CHARSET=UTF8 forces the
     * pass-through for applications that handle UTF-8 themselves.
     */
#ifdef _WIN32
    dbc->ansi_charset = !cs_ascii_equal(o->charset, "UTF8") && !cs_ascii_equal(o->charset, "UTF-8");
#else
    dbc->ansi_charset = cs_ascii_equal(o->charset, "ANSI");
#endif
    return SQL_SUCCESS;
}

static SQLRETURN SQL_API cs_i_SQLConnect(SQLHDBC connection, SQLCHAR *server,
    SQLSMALLINT server_len, SQLCHAR *user, SQLSMALLINT user_len,
    SQLCHAR *password, SQLSMALLINT password_len) {
    cs_dbc *dbc = (cs_dbc *)connection;
    cs_conn_options o;
    if (!cs_valid_handle(connection, SQL_HANDLE_DBC)) return SQL_INVALID_HANDLE;
    memset(&o, 0, sizeof(o));
    if (server) { size_t n = cs_input_len(server, server_len); if (n >= sizeof(o.dsn)) n = sizeof(o.dsn)-1; memcpy(o.dsn, server, n); }
    if (user) { size_t n = cs_input_len(user, user_len); if (n >= sizeof(o.user)) n = sizeof(o.user)-1; memcpy(o.user, user, n); }
    if (password) { size_t n = cs_input_len(password, password_len); if (n >= sizeof(o.password)) n = sizeof(o.password)-1; memcpy(o.password, password, n); }
    return cs_connect_options(dbc, &o);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLConnect(SQLHDBC connection, SQLCHAR *server,
    SQLSMALLINT server_len, SQLCHAR *user, SQLSMALLINT user_len,
    SQLCHAR *password, SQLSMALLINT password_len) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLConnect(connection, server, server_len, user, user_len, password, password_len);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLConnectW(SQLHDBC connection, SQLWCHAR *server,
    SQLSMALLINT server_len, SQLWCHAR *user, SQLSMALLINT user_len,
    SQLWCHAR *password, SQLSMALLINT password_len) {
    char *a = cs_utf16_to_utf8(server, server_len), *b = cs_utf16_to_utf8(user, user_len),
         *c = cs_utf16_to_utf8(password, password_len);
    SQLRETURN rc;
    if (!a || !b || !c) { free(a); free(b); free(c); return SQL_ERROR; }
    rc = SQLConnect(connection, (SQLCHAR *)a, SQL_NTS, (SQLCHAR *)b, SQL_NTS, (SQLCHAR *)c, SQL_NTS);
    free(a); free(b); free(c); return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLConnectW(SQLHDBC connection, SQLWCHAR *server,
    SQLSMALLINT server_len, SQLWCHAR *user, SQLSMALLINT user_len,
    SQLWCHAR *password, SQLSMALLINT password_len) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLConnectW(connection, server, server_len, user, user_len, password, password_len);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLConnectA(SQLHDBC c, SQLCHAR *s, SQLSMALLINT sl,
    SQLCHAR *u, SQLSMALLINT ul, SQLCHAR *p, SQLSMALLINT pl) { return SQLConnect(c,s,sl,u,ul,p,pl); }

CSODBC_EXPORT SQLRETURN SQL_API SQLConnectA(SQLHDBC c, SQLCHAR *s, SQLSMALLINT sl,
    SQLCHAR *u, SQLSMALLINT ul, SQLCHAR *p, SQLSMALLINT pl) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, c);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLConnectA(c, s, sl, u, ul, p, pl);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static void cs_conn_escape(char *out, size_t cap, const char *value) {
    size_t n = 0;
    if (cap < 3) return;
    out[n++] = '{';
    while (*value && n + 2 < cap) { if (*value == '}') out[n++] = '}'; out[n++] = *value++; }
    out[n++] = '}'; out[n] = '\0';
}

/*
 * The completed connection string is handed back to the application, which
 * frequently persists it. It therefore never carries the password.
 */
static void cs_build_connection_string(cs_dbc *dbc, char *out, size_t cap) {
    char eh[600], eu[600], ed[1100], eds[600];
    size_t n;
    cs_conn_escape(eh, sizeof(eh), dbc->host); cs_conn_escape(eu, sizeof(eu), dbc->user);
    cs_conn_escape(ed, sizeof(ed), dbc->database); cs_conn_escape(eds, sizeof(eds), dbc->dsn);
    n = 0;
    if (dbc->dsn[0]) n = (size_t)snprintf(out, cap, "DSN=%s;", eds);
    else n = (size_t)snprintf(out, cap, "DRIVER={CubeSQL ODBC Driver};");
    if (n < cap)
        snprintf(out + n, cap - n, "SERVER=%s;PORT=%s;UID=%s;DATABASE=%s;ENCRYPTION=%s;TIMEOUT=%lu;",
                 eh, dbc->port, eu, ed, dbc->encryption, (unsigned long)dbc->login_timeout);
    out[cap - 1] = '\0';
}

/*
 * Shared by the ANSI and Unicode entry points: decides whether the Driver
 * Manager's completion flag calls for the login dialog, shows it, and connects.
 *
 * The first release ignored both the window handle and the completion flag, so
 * a data source without a stored password (they are never stored) simply failed
 * with "UID is required" instead of asking the user for one.
 */
static SQLRETURN cs_driver_connect(cs_dbc *dbc, SQLHWND window,
                                   cs_conn_options *o, SQLUSMALLINT completion) {
    int need_prompt = 0;
    SQLRETURN rc;

    cs_read_dsn(o);
    cs_conn_apply_defaults(o);

    if (completion == SQL_DRIVER_PROMPT) need_prompt = 1;
    else if (completion == SQL_DRIVER_COMPLETE || completion == SQL_DRIVER_COMPLETE_REQUIRED)
        need_prompt = (!o->user[0] || !(o->seen & CS_OPT_SEEN_PWD));

#ifdef _WIN32
    if (need_prompt && window) {
        for (;;) {
            if (!cs_prompt_dialog((HWND)window, o, 1)) {
                cs_diag_clear(&dbc->h);
                return SQL_NO_DATA;   /* the user cancelled */
            }
            rc = cs_connect_options(dbc, o);
            if (SQL_SUCCEEDED(rc)) return rc;
            {
                /* Show why it failed and let the user correct the entries. */
                SQLCHAR state[6] = "", message[512] = "";
                SQLINTEGER native = 0; SQLSMALLINT len = 0;
                if (SQLGetDiagRec(SQL_HANDLE_DBC, (SQLHANDLE)dbc, 1, state, &native,
                                  message, sizeof(message), &len) != SQL_SUCCESS)
                    strcpy((char *)message, "The connection could not be opened.");
                if (MessageBoxA((HWND)window, (const char *)message,
                                "CubeSQL ODBC Driver",
                                MB_RETRYCANCEL | MB_ICONEXCLAMATION) != IDRETRY)
                    return rc;
            }
        }
    }
#endif
    if (need_prompt && !window && completion == SQL_DRIVER_PROMPT)
        return cs_diag_add(&dbc->h, "IM008", 0,
                           "SQL_DRIVER_PROMPT requires a parent window handle");
    return cs_connect_options(dbc, o);
}

static SQLRETURN SQL_API cs_i_SQLDriverConnect(SQLHDBC connection, SQLHWND window,
    SQLCHAR *input, SQLSMALLINT input_len, SQLCHAR *output, SQLSMALLINT output_cap,
    SQLSMALLINT *output_len, SQLUSMALLINT completion) {
    cs_dbc *dbc = (cs_dbc *)connection;
    cs_conn_options o; char *text, canonical[3072]; SQLRETURN rc, copy_rc; SQLLEN n = 0;
    if (!cs_valid_handle(connection, SQL_HANDLE_DBC)) return SQL_INVALID_HANDLE;
    memset(&o, 0, sizeof(o));
    text = cs_strndup0((const char *)(input ? input : (SQLCHAR *)""), cs_input_len(input, input_len));
    if (!text) return cs_diag_add(&dbc->h, "HY001", 0, "Memory allocation error");
    if (!cs_parse_connection_string(&o, text)) { free(text); return cs_diag_add(&dbc->h, "IM012", 0, "Invalid connection string syntax"); }
    free(text);
    rc = cs_driver_connect(dbc, window, &o, completion);
    if (!SQL_SUCCEEDED(rc)) return rc;
    cs_build_connection_string(dbc, canonical, sizeof(canonical));
    copy_rc = cs_copy_utf8(output, output_cap, &n, canonical, &dbc->h);
    if (output_len) *output_len = (SQLSMALLINT)n;
    return copy_rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLDriverConnect(SQLHDBC connection, SQLHWND window,
    SQLCHAR *input, SQLSMALLINT input_len, SQLCHAR *output, SQLSMALLINT output_cap,
    SQLSMALLINT *output_len, SQLUSMALLINT completion) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLDriverConnect(connection, window, input, input_len, output, output_cap, output_len, completion);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLDriverConnectW(SQLHDBC connection, SQLHWND window,
    SQLWCHAR *input, SQLSMALLINT input_len, SQLWCHAR *output, SQLSMALLINT output_cap,
    SQLSMALLINT *output_len, SQLUSMALLINT completion) {
    cs_dbc *dbc = (cs_dbc *)connection; cs_conn_options o; char *text, canonical[3072];
    SQLRETURN rc, copy_rc; SQLLEN n = 0;
    if (!cs_valid_handle(connection, SQL_HANDLE_DBC)) return SQL_INVALID_HANDLE;
    memset(&o, 0, sizeof(o));
    text = cs_utf16_to_utf8(input, input_len);
    if (!text) return cs_diag_add(&dbc->h, "HY001", 0, "Memory allocation error");
    if (!cs_parse_connection_string(&o, text)) { free(text); return cs_diag_add(&dbc->h, "IM012", 0, "Invalid connection string syntax"); }
    free(text); rc = cs_driver_connect(dbc, window, &o, completion); if (!SQL_SUCCEEDED(rc)) return rc;
    cs_build_connection_string(dbc, canonical, sizeof(canonical));
    copy_rc = cs_copy_utf16(output, output_cap, &n, canonical, &dbc->h);
    if (output_len) *output_len = (SQLSMALLINT)n;
    return copy_rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLDriverConnectW(SQLHDBC connection, SQLHWND window,
    SQLWCHAR *input, SQLSMALLINT input_len, SQLWCHAR *output, SQLSMALLINT output_cap,
    SQLSMALLINT *output_len, SQLUSMALLINT completion) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLDriverConnectW(connection, window, input, input_len, output, output_cap, output_len, completion);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLDriverConnectA(SQLHDBC c, SQLHWND w, SQLCHAR *i,
    SQLSMALLINT il, SQLCHAR *o, SQLSMALLINT oc, SQLSMALLINT *ol, SQLUSMALLINT f) {
    return SQLDriverConnect(c,w,i,il,o,oc,ol,f);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLDriverConnectA(SQLHDBC c, SQLHWND w, SQLCHAR *i,
    SQLSMALLINT il, SQLCHAR *o, SQLSMALLINT oc, SQLSMALLINT *ol, SQLUSMALLINT f) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, c);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLDriverConnectA(c, w, i, il, o, oc, ol, f);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLBrowseConnect(SQLHDBC connection, SQLCHAR *input,
    SQLSMALLINT input_len, SQLCHAR *output, SQLSMALLINT output_cap, SQLSMALLINT *output_len) {
    cs_dbc *dbc = (cs_dbc *)connection; cs_conn_options o; char *text; const char *needed = NULL; SQLLEN n = 0;
    if (!cs_valid_handle(connection, SQL_HANDLE_DBC)) return SQL_INVALID_HANDLE;
    cs_diag_clear(&dbc->h); memset(&o, 0, sizeof(o));
    text = cs_strndup0((const char *)(input ? input : (SQLCHAR *)""), cs_input_len(input, input_len));
    if (!text) return cs_diag_add(&dbc->h, "HY001", 0, "Memory allocation error");
    if (!cs_parse_connection_string(&o, text)) { free(text); return cs_diag_add(&dbc->h, "IM012", 0, "Invalid connection string syntax"); }
    free(text); cs_read_dsn(&o);
    if (!o.host[0]) needed = "SERVER:Server={localhost};PORT:Port={4430};";
    else if (!o.user[0]) needed = "UID:User ID=?;PWD:Password=?;";
    if (needed) { SQLRETURN rc = cs_copy_utf8(output, output_cap, &n, needed, &dbc->h); if (output_len) *output_len=(SQLSMALLINT)n; return rc == SQL_SUCCESS ? SQL_NEED_DATA : rc; }
    return cs_connect_options(dbc, &o);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLBrowseConnect(SQLHDBC connection, SQLCHAR *input,
    SQLSMALLINT input_len, SQLCHAR *output, SQLSMALLINT output_cap, SQLSMALLINT *output_len) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLBrowseConnect(connection, input, input_len, output, output_cap, output_len);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

/*
 * SQLDisconnect frees every statement allocated on the connection, as the spec
 * requires. The previous behaviour of only closing their cursors left the
 * statements alive, so the usual Disconnect -> SQLFreeHandle(DBC) sequence
 * failed with HY010 and leaked the handles.
 */
static SQLRETURN SQL_API cs_i_SQLDisconnect(SQLHDBC connection) {
    cs_dbc *dbc = (cs_dbc *)connection;
    if (!cs_valid_handle(connection, SQL_HANDLE_DBC)) return SQL_INVALID_HANDLE;
    cs_diag_clear(&dbc->h);
    if (!dbc->connected) return cs_diag_add(&dbc->h, "08003", 0, "Connection is not open");
    /* An uncommitted transaction is rolled back, not silently committed. */
    if (dbc->in_transaction && dbc->db && !dbc->dead) {
        cubesql_rollback(dbc->db);
        cubesql_clear_errors(dbc->db);
    }
    dbc->in_transaction = 0;
    while (dbc->statements) {
        cs_stmt *stmt = dbc->statements;
        dbc->statements = stmt->next;
        cs_stmt_close(stmt);
        free(stmt->sql);
        stmt->h.magic = 0;
        free(stmt);
    }
    if (dbc->db) cubesql_disconnect(dbc->db, dbc->dead ? kFALSE : kTRUE);
    dbc->db = NULL; dbc->connected = 0; dbc->dead = 0;
    dbc->autocommit = SQL_AUTOCOMMIT_ON;
    memset(dbc->password, 0, sizeof(dbc->password));
    return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLDisconnect(SQLHDBC connection) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLDisconnect(connection);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLSetEnvAttr(SQLHENV environment, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER length) {
    cs_env *env = (cs_env *)environment; SQLULEN v = (SQLULEN)(uintptr_t)value;
    (void)length;
    if (!cs_valid_handle(environment, SQL_HANDLE_ENV)) return SQL_INVALID_HANDLE;
    cs_diag_clear(&env->h);
    if (attribute == SQL_ATTR_ODBC_VERSION) {
        if (v != SQL_OV_ODBC2 && v != SQL_OV_ODBC3 && v != SQL_OV_ODBC3_80)
            return cs_diag_add(&env->h, "HY024", 0, "Invalid ODBC version");
        env->odbc_version = (SQLINTEGER)v; return SQL_SUCCESS;
    }
    if (attribute == SQL_ATTR_OUTPUT_NTS) {
        if (v != SQL_TRUE) return cs_diag_add(&env->h, "HYC00", 0, "Only null-terminated output is supported");
        env->output_nts = SQL_TRUE; return SQL_SUCCESS;
    }
    if (attribute == SQL_ATTR_CONNECTION_POOLING) { env->connection_pooling = v; return SQL_SUCCESS; }
    if (attribute == SQL_ATTR_CP_MATCH) { env->cp_match = v; return SQL_SUCCESS; }
    return cs_diag_add(&env->h, "HY092", 0, "Invalid environment attribute %ld", (long)attribute);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetEnvAttr(SQLHENV environment, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_ENV, environment);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetEnvAttr(environment, attribute, value, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetEnvAttr(SQLHENV environment, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER capacity, SQLINTEGER *length) {
    cs_env *env = (cs_env *)environment; (void)capacity;
    if (!cs_valid_handle(environment, SQL_HANDLE_ENV)) return SQL_INVALID_HANDLE;
    cs_diag_clear(&env->h);
    if (attribute == SQL_ATTR_ODBC_VERSION) { if (value) *(SQLINTEGER *)value=env->odbc_version; if(length)*length=sizeof(SQLINTEGER); return SQL_SUCCESS; }
    if (attribute == SQL_ATTR_OUTPUT_NTS) { if(value)*(SQLINTEGER *)value=env->output_nts; if(length)*length=sizeof(SQLINTEGER); return SQL_SUCCESS; }
    if (attribute == SQL_ATTR_CONNECTION_POOLING) { if(value)*(SQLUINTEGER *)value=(SQLUINTEGER)env->connection_pooling; if(length)*length=sizeof(SQLUINTEGER); return SQL_SUCCESS; }
    if (attribute == SQL_ATTR_CP_MATCH) { if(value)*(SQLUINTEGER *)value=(SQLUINTEGER)env->cp_match; if(length)*length=sizeof(SQLUINTEGER); return SQL_SUCCESS; }
    return cs_diag_add(&env->h, "HY092", 0, "Invalid environment attribute %ld", (long)attribute);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetEnvAttr(SQLHENV environment, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER capacity, SQLINTEGER *length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_ENV, environment);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetEnvAttr(environment, attribute, value, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLSetConnectAttr(SQLHDBC connection, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER length) {
    cs_dbc *dbc = (cs_dbc *)connection; SQLULEN v=(SQLULEN)(uintptr_t)value; int rc;
    if (!cs_valid_handle(connection, SQL_HANDLE_DBC)) return SQL_INVALID_HANDLE;
    cs_diag_clear(&dbc->h);
    switch (attribute) {
        case SQL_ATTR_AUTOCOMMIT:
            if (v != SQL_AUTOCOMMIT_ON && v != SQL_AUTOCOMMIT_OFF) return cs_diag_add(&dbc->h,"HY024",0,"Invalid autocommit value");
            if (dbc->autocommit == v) return SQL_SUCCESS;
            if (dbc->connected) {
                if (v == SQL_AUTOCOMMIT_OFF) rc = cubesql_begintransaction(dbc->db);
                else rc = cubesql_commit(dbc->db);
                if (rc != CUBESQL_NOERR) { cs_map_sdk_error(&dbc->h,dbc->db,rc,"change autocommit"); return SQL_ERROR; }
                dbc->in_transaction = (v == SQL_AUTOCOMMIT_OFF);
            }
            dbc->autocommit=v; return SQL_SUCCESS;
        case SQL_ATTR_ACCESS_MODE:
            if (v != SQL_MODE_READ_ONLY && v != SQL_MODE_READ_WRITE) return cs_diag_add(&dbc->h,"HY024",0,"Invalid access mode");
            dbc->access_mode=v; return SQL_SUCCESS;
        case SQL_ATTR_LOGIN_TIMEOUT: dbc->login_timeout=v; return SQL_SUCCESS;
        case SQL_ATTR_CONNECTION_TIMEOUT: dbc->connection_timeout=v; return SQL_SUCCESS;
        case SQL_ATTR_TXN_ISOLATION:
            if (v != SQL_TXN_SERIALIZABLE) {
                dbc->txn_isolation=SQL_TXN_SERIALIZABLE;
                return cs_diag_warn(&dbc->h,"01S02","CubeSQL only provides serializable transactions");
            }
            dbc->txn_isolation=v; return SQL_SUCCESS;
        /*
         * Attributes the driver has to accept because virtually every ODBC
         * consumer sets them. Rejecting them aborted connections outright.
         */
        case SQL_ATTR_METADATA_ID:
            if (v != SQL_TRUE && v != SQL_FALSE) return cs_diag_add(&dbc->h,"HY024",0,"Invalid metadata identifier value");
            dbc->metadata_id=v; return SQL_SUCCESS;
        case SQL_ATTR_QUIET_MODE: dbc->quiet_mode=value; return SQL_SUCCESS;
        case SQL_ATTR_ODBC_CURSORS: dbc->odbc_cursors=v; return SQL_SUCCESS;
        case SQL_ATTR_PACKET_SIZE:
            /* CubeSQL sizes its own frames; report the substitution honestly. */
            dbc->packet_size=0;
            if (v) return cs_diag_warn(&dbc->h,"01S02","The network packet size is fixed by the CubeSQL protocol");
            return SQL_SUCCESS;
        case SQL_ATTR_ASYNC_ENABLE:
            if (v != SQL_ASYNC_ENABLE_OFF) return cs_diag_add(&dbc->h,"HYC00",0,"Asynchronous execution is not supported");
            dbc->async_enable=v; return SQL_SUCCESS;
        case SQL_ATTR_TRACE: dbc->trace=v; return SQL_SUCCESS;
        case SQL_ATTR_TRACEFILE: case SQL_ATTR_TRANSLATE_LIB: return SQL_SUCCESS;
        case SQL_ATTR_TRANSLATE_OPTION: dbc->translate_option=v; return SQL_SUCCESS;
#ifdef SQL_ATTR_ANSI_APP
        case SQL_ATTR_ANSI_APP:
            /*
             * The Driver Manager probes this on Unicode drivers. Returning an
             * error is the documented way of saying "I do not need to know".
             */
            return SQL_ERROR;
#endif
        case SQL_ATTR_AUTO_IPD: case SQL_ATTR_CONNECTION_DEAD:
            return cs_diag_add(&dbc->h,"HY092",0,"Connection attribute %ld is read-only",(long)attribute);
        case SQL_ATTR_CURRENT_CATALOG: {
            char *catalog;
            if (!value) return cs_diag_add(&dbc->h,"HY009",0,"Catalog is null");
            catalog=cs_strndup0((const char *)value,length==SQL_NTS?strlen((const char *)value):(size_t)length);
            if(!catalog)return cs_diag_add(&dbc->h,"HY001",0,"Memory allocation error");
            if(!dbc->connected){free(catalog);return cs_diag_add(&dbc->h,"08003",0,"Connection is not open");}
            rc=cubesql_set_database(dbc->db,catalog);
            if(rc==CUBESQL_NOERR)cs_option_set(dbc->database,sizeof(dbc->database),catalog);
            free(catalog); if(rc!=CUBESQL_NOERR){cs_map_sdk_error(&dbc->h,dbc->db,rc,"set catalog");return SQL_ERROR;} return SQL_SUCCESS;
        }
        default: return cs_diag_add(&dbc->h,"HYC00",0,"Connection attribute %ld is not supported",(long)attribute);
    }
}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetConnectAttr(SQLHDBC connection, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetConnectAttr(connection, attribute, value, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLSetConnectAttrW(SQLHDBC connection, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER length) {
    char *utf8; SQLRETURN rc;
    if(attribute!=SQL_ATTR_CURRENT_CATALOG)return SQLSetConnectAttr(connection,attribute,value,length);
    utf8=cs_utf16_to_utf8((SQLWCHAR *)value,length); if(!utf8)return SQL_ERROR;
    rc=SQLSetConnectAttr(connection,attribute,utf8,SQL_NTS); free(utf8); return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetConnectAttrW(SQLHDBC connection, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetConnectAttrW(connection, attribute, value, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetConnectAttr(SQLHDBC connection, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER capacity, SQLINTEGER *length) {
    cs_dbc *dbc=(cs_dbc *)connection; SQLLEN n=0; SQLRETURN rc;
    if(!cs_valid_handle(connection,SQL_HANDLE_DBC))return SQL_INVALID_HANDLE;
    cs_diag_clear(&dbc->h);
#define CS_DBC_NUM(x) do { if(value)*(SQLULEN *)value=(SQLULEN)(x); if(length)*length=(SQLINTEGER)sizeof(SQLULEN); return SQL_SUCCESS; } while(0)
    switch(attribute){
        case SQL_ATTR_AUTOCOMMIT: CS_DBC_NUM(dbc->autocommit);
        case SQL_ATTR_ACCESS_MODE: CS_DBC_NUM(dbc->access_mode);
        case SQL_ATTR_LOGIN_TIMEOUT: CS_DBC_NUM(dbc->login_timeout);
        case SQL_ATTR_CONNECTION_TIMEOUT: CS_DBC_NUM(dbc->connection_timeout);
        case SQL_ATTR_TXN_ISOLATION: CS_DBC_NUM(dbc->txn_isolation);
        case SQL_ATTR_CONNECTION_DEAD: CS_DBC_NUM((dbc->connected&&!dbc->dead)?SQL_CD_FALSE:SQL_CD_TRUE);
        case SQL_ATTR_METADATA_ID: CS_DBC_NUM(dbc->metadata_id);
        case SQL_ATTR_PACKET_SIZE: CS_DBC_NUM(dbc->packet_size);
        case SQL_ATTR_ODBC_CURSORS: CS_DBC_NUM(dbc->odbc_cursors);
        case SQL_ATTR_ASYNC_ENABLE: CS_DBC_NUM(dbc->async_enable);
        case SQL_ATTR_TRACE: CS_DBC_NUM(dbc->trace);
        case SQL_ATTR_TRANSLATE_OPTION: CS_DBC_NUM(dbc->translate_option);
        case SQL_ATTR_AUTO_IPD: CS_DBC_NUM(SQL_FALSE);
        case SQL_ATTR_QUIET_MODE:
            if(value)*(SQLPOINTER *)value=dbc->quiet_mode;
            if(length)*length=(SQLINTEGER)sizeof(SQLPOINTER);
            return SQL_SUCCESS;
        case SQL_ATTR_CURRENT_CATALOG:
            rc=cs_copy_utf8((SQLCHAR *)value,capacity,&n,dbc->database,&dbc->h); if(length)*length=(SQLINTEGER)n; return rc;
        default:return cs_diag_add(&dbc->h,"HY092",0,"Invalid connection attribute %ld",(long)attribute);
    }
#undef CS_DBC_NUM
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetConnectAttr(SQLHDBC connection, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER capacity, SQLINTEGER *length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetConnectAttr(connection, attribute, value, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetConnectAttrW(SQLHDBC connection, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER capacity, SQLINTEGER *length) {
    cs_dbc *dbc=(cs_dbc *)connection; SQLLEN n=0; SQLRETURN rc;
    if(attribute!=SQL_ATTR_CURRENT_CATALOG)return SQLGetConnectAttr(connection,attribute,value,capacity,length);
    if(!cs_valid_handle(connection,SQL_HANDLE_DBC))return SQL_INVALID_HANDLE; cs_diag_clear(&dbc->h);
    rc=cs_copy_utf16((SQLWCHAR *)value,capacity/sizeof(SQLWCHAR),&n,dbc->database,&dbc->h);
    if(length)*length=(SQLINTEGER)(n*sizeof(SQLWCHAR)); return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetConnectAttrW(SQLHDBC connection, SQLINTEGER attribute,
    SQLPOINTER value, SQLINTEGER capacity, SQLINTEGER *length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetConnectAttrW(connection, attribute, value, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLSetConnectOption(SQLHDBC c,SQLUSMALLINT a,SQLULEN v){return SQLSetConnectAttr(c,a,(SQLPOINTER)(uintptr_t)v,0);}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetConnectOption(SQLHDBC c,SQLUSMALLINT a,SQLULEN v) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, c);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetConnectOption(c, a, v);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLGetConnectOption(SQLHDBC c,SQLUSMALLINT a,SQLPOINTER v){return SQLGetConnectAttr(c,a,v,0,NULL);}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetConnectOption(SQLHDBC c,SQLUSMALLINT a,SQLPOINTER v) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, c);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetConnectOption(c, a, v);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLEndTran(SQLSMALLINT type,SQLHANDLE handle,SQLSMALLINT completion){
    cs_dbc *dbc; cs_env *env; int rc;
    if(type==SQL_HANDLE_ENV){
        if(!cs_valid_handle(handle,SQL_HANDLE_ENV))return SQL_INVALID_HANDLE; env=(cs_env *)handle; cs_diag_clear(&env->h);
        /* Lock order is always environment then connection, matching
           SQLFreeHandle, so these two paths cannot deadlock against it. */
        for(dbc=env->connections;dbc;dbc=dbc->next){
            SQLRETURN sub;
            if(!dbc->connected)continue;
            cs_mutex_lock(&dbc->lock);
            rc=completion==SQL_COMMIT?cubesql_commit(dbc->db):cubesql_rollback(dbc->db);
            if(rc==CUBESQL_NOERR){dbc->in_transaction=0;sub=SQL_SUCCESS;}
            else{cs_map_sdk_error(&env->h,dbc->db,rc,"end transaction");sub=SQL_ERROR;}
            cs_mutex_unlock(&dbc->lock);
            if(sub==SQL_ERROR)return SQL_ERROR;
        }
        return SQL_SUCCESS;
    }
    if(type!=SQL_HANDLE_DBC||!cs_valid_handle(handle,SQL_HANDLE_DBC))return SQL_INVALID_HANDLE;
    dbc=(cs_dbc *)handle; cs_diag_clear(&dbc->h);
    if(!dbc->connected)return cs_diag_add(&dbc->h,"08003",0,"Connection is not open");
    if(completion!=SQL_COMMIT&&completion!=SQL_ROLLBACK)return cs_diag_add(&dbc->h,"HY012",0,"Invalid transaction operation");
    rc=completion==SQL_COMMIT?cubesql_commit(dbc->db):cubesql_rollback(dbc->db);
    dbc->in_transaction=0;
    if(rc!=CUBESQL_NOERR){cs_map_sdk_error(&dbc->h,dbc->db,rc,"end transaction");return SQL_ERROR;}
    if(dbc->autocommit==SQL_AUTOCOMMIT_OFF){rc=cubesql_begintransaction(dbc->db);if(rc!=CUBESQL_NOERR){cs_map_sdk_error(&dbc->h,dbc->db,rc,"begin transaction");return SQL_ERROR;}dbc->in_transaction=1;}
    return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLEndTran(SQLSMALLINT type,SQLHANDLE handle,SQLSMALLINT completion) {
    cs_mutex *cs__m = cs_handle_lock(type, handle);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLEndTran(type, handle, completion);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLTransact(SQLHENV env,SQLHDBC dbc,SQLUSMALLINT op){return dbc?SQLEndTran(SQL_HANDLE_DBC,dbc,op):SQLEndTran(SQL_HANDLE_ENV,env,op);}

static SQLRETURN SQL_API cs_i_SQLFreeStmt(SQLHSTMT statement,SQLUSMALLINT option){
    cs_stmt *stmt=(cs_stmt *)statement; SQLUSMALLINT i;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE; cs_diag_clear(&stmt->h);
    if(option==SQL_DROP)return SQLFreeHandle(SQL_HANDLE_STMT,statement);
    if(option==SQL_CLOSE){cs_stmt_close(stmt);return SQL_SUCCESS;}
    if(option==SQL_UNBIND){memset(stmt->columns,0,sizeof(stmt->columns));return SQL_SUCCESS;}
    if(option==SQL_RESET_PARAMS){for(i=0;i<stmt->num_params;i++)free(stmt->params[i].at_exec);memset(stmt->params,0,sizeof(stmt->params));stmt->num_params=0;return SQL_SUCCESS;}
    return cs_diag_add(&stmt->h,"HY092",0,"Invalid free-statement option");
}

CSODBC_EXPORT SQLRETURN SQL_API SQLFreeStmt(SQLHSTMT statement,SQLUSMALLINT option) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLFreeStmt(statement, option);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLCloseCursor(SQLHSTMT statement){
    cs_stmt *stmt=(cs_stmt *)statement;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE; cs_diag_clear(&stmt->h);
    if(!stmt->cursor)return cs_diag_add(&stmt->h,"24000",0,"No cursor is open"); cs_stmt_close(stmt); return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLCloseCursor(SQLHSTMT statement) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLCloseCursor(statement);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

/*
 * Deliberately not generated: SQLCancel may be called from another thread while
 * a call is in flight on this connection, so it must not block on the
 * connection mutex.
 *
 * When the mutex is free nothing is executing, and the spec says SQLCancel then
 * behaves like SQLFreeStmt(SQL_CLOSE). That matters because CubeSQL's only
 * cancellation primitive is cubesql_cancel(), which hard-closes the socket and
 * therefore destroys the whole connection: applications that call SQLCancel to
 * discard a cursor must not lose their connection over it.
 */
CSODBC_EXPORT SQLRETURN SQL_API SQLCancel(SQLHSTMT statement){
    cs_stmt *stmt=(cs_stmt *)statement; cs_dbc *dbc;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;
    dbc=stmt->dbc;
    if(cs_mutex_trylock(&dbc->lock)){
        cs_diag_clear(&stmt->h);
        if(stmt->need_data_active){stmt->need_data_active=0;stmt->at_exec_param=0;}
        cs_stmt_close(stmt);
        cs_mutex_unlock(&dbc->lock);
        return SQL_SUCCESS;
    }
    /* A call is in flight. Dropping the socket is the only way to interrupt it. */
    if(dbc->connected&&dbc->db){dbc->dead=1;cubesql_cancel(dbc->db);}
    return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLCancelHandle(SQLSMALLINT type,SQLHANDLE handle){
    if(type==SQL_HANDLE_STMT)return SQLCancel((SQLHSTMT)handle);
    if(type==SQL_HANDLE_DBC)return cs_valid_handle(handle,SQL_HANDLE_DBC)?SQL_SUCCESS:SQL_INVALID_HANDLE;
    return SQL_INVALID_HANDLE;
}

static SQLRETURN SQL_API cs_i_SQLSetStmtAttr(SQLHSTMT statement,SQLINTEGER attribute,
    SQLPOINTER value,SQLINTEGER length){
    cs_stmt *s=(cs_stmt *)statement; SQLULEN v=(SQLULEN)(uintptr_t)value; (void)length;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE; cs_diag_clear(&s->h);
    switch(attribute){
        case SQL_ATTR_QUERY_TIMEOUT:s->query_timeout=v;return SQL_SUCCESS;
        case SQL_ATTR_MAX_ROWS:s->max_rows=v;return SQL_SUCCESS;
        case SQL_ATTR_MAX_LENGTH:s->max_length=v;return SQL_SUCCESS;
        /* Rowset binding: block fetch is what Excel, Power Query and ADO use. */
        /*
         * SQL_ROWSET_SIZE (9) is the ODBC 2.x spelling of SQL_ATTR_ROW_ARRAY_SIZE
         * (27). The Driver Manager rewrites the 3.x attribute into this one when
         * it thinks it is talking to a 2.x driver, and without this case block
         * fetch was rejected with HYC00 "Statement attribute 9 is not supported".
         */
        case SQL_ROWSET_SIZE:
        case SQL_ATTR_ROW_ARRAY_SIZE:
            if(v<1)return cs_diag_add(&s->h,"HY024",0,"Row array size must be at least one");
            s->row_array_size=v;return SQL_SUCCESS;
        case SQL_ATTR_ROW_BIND_TYPE:s->row_bind_type=v;return SQL_SUCCESS;
        case SQL_ATTR_ROW_BIND_OFFSET_PTR:s->row_bind_offset=(SQLULEN *)value;return SQL_SUCCESS;
        case SQL_ATTR_ROWS_FETCHED_PTR:s->rows_fetched=(SQLULEN *)value;return SQL_SUCCESS;
        case SQL_ATTR_ROW_STATUS_PTR:s->row_status=(SQLUSMALLINT *)value;return SQL_SUCCESS;
        case SQL_ATTR_ROW_OPERATION_PTR:s->row_operation=(SQLUSMALLINT *)value;return SQL_SUCCESS;
        case SQL_ATTR_PARAMSET_SIZE:
            if(v<1)return cs_diag_add(&s->h,"HY024",0,"Parameter set size must be at least one");
            s->paramset_size=v;return SQL_SUCCESS;
        case SQL_ATTR_PARAM_BIND_TYPE:s->param_bind_type=v;return SQL_SUCCESS;
        case SQL_ATTR_PARAM_BIND_OFFSET_PTR:s->param_bind_offset=(SQLULEN *)value;return SQL_SUCCESS;
        case SQL_ATTR_PARAMS_PROCESSED_PTR:s->params_processed=(SQLULEN *)value;return SQL_SUCCESS;
        case SQL_ATTR_PARAM_STATUS_PTR:s->param_status=(SQLUSMALLINT *)value;return SQL_SUCCESS;
        case SQL_ATTR_PARAM_OPERATION_PTR:s->param_operation=(SQLUSMALLINT *)value;return SQL_SUCCESS;
        case SQL_ATTR_CURSOR_TYPE:
            /*
             * Every cursor CubeSQL can give us is a client-side static snapshot.
             * Substituting with a warning is what the spec asks for; the old
             * code returned 01S02 through cs_diag_add, which reported SQL_ERROR
             * and made keyset or dynamic cursors a hard failure.
             */
            if(v==SQL_CURSOR_FORWARD_ONLY||v==SQL_CURSOR_STATIC){s->cursor_type=v;return SQL_SUCCESS;}
            s->cursor_type=SQL_CURSOR_STATIC;
            return cs_diag_warn(&s->h,"01S02","Cursor type changed to static");
        case SQL_ATTR_CONCURRENCY:
            if(v==SQL_CONCUR_READ_ONLY){s->concurrency=v;return SQL_SUCCESS;}
            s->concurrency=SQL_CONCUR_READ_ONLY;
            return cs_diag_warn(&s->h,"01S02","Concurrency changed to read-only");
        case SQL_ATTR_CURSOR_SCROLLABLE:
            s->cursor_scrollable=v;
            s->cursor_type=(v==SQL_SCROLLABLE)?SQL_CURSOR_STATIC:SQL_CURSOR_FORWARD_ONLY;
            return SQL_SUCCESS;
        case SQL_ATTR_CURSOR_SENSITIVITY:
            if(v==SQL_INSENSITIVE||v==SQL_UNSPECIFIED){s->cursor_sensitivity=v;return SQL_SUCCESS;}
            s->cursor_sensitivity=SQL_INSENSITIVE;
            return cs_diag_warn(&s->h,"01S02","Cursor sensitivity changed to insensitive");
        case SQL_ATTR_KEYSET_SIZE:s->keyset_size=v;return SQL_SUCCESS;
        case SQL_ATTR_SIMULATE_CURSOR:s->simulate_cursor=v;return SQL_SUCCESS;
        case SQL_ATTR_NOSCAN:s->noscan=v;return SQL_SUCCESS;
        case SQL_ATTR_METADATA_ID:
            if(v!=SQL_TRUE&&v!=SQL_FALSE)return cs_diag_add(&s->h,"HY024",0,"Invalid metadata identifier value");
            s->metadata_id=v;return SQL_SUCCESS;
        case SQL_ATTR_ASYNC_ENABLE:
            if(v!=SQL_ASYNC_ENABLE_OFF)return cs_diag_add(&s->h,"HYC00",0,"Asynchronous execution is not supported");
            s->async_enable=v;return SQL_SUCCESS;
        case SQL_ATTR_RETRIEVE_DATA:
            if(v==SQL_RD_ON){s->retrieve_data=v;return SQL_SUCCESS;}
            s->retrieve_data=SQL_RD_ON;
            return cs_diag_warn(&s->h,"01S02","Data retrieval cannot be disabled");
        case SQL_ATTR_USE_BOOKMARKS:
            if(v==SQL_UB_OFF){s->use_bookmarks=v;return SQL_SUCCESS;}
            s->use_bookmarks=SQL_UB_OFF;
            return cs_diag_warn(&s->h,"01S02","Bookmarks are not supported");
        case SQL_ATTR_ENABLE_AUTO_IPD:
            if(v==SQL_FALSE)return SQL_SUCCESS;
            return cs_diag_warn(&s->h,"01S02","Automatic parameter description is not available");
        case SQL_ATTR_APP_ROW_DESC:case SQL_ATTR_APP_PARAM_DESC:
        case SQL_ATTR_IMP_ROW_DESC:case SQL_ATTR_IMP_PARAM_DESC:
            return cs_diag_add(&s->h,"HYC00",0,"Explicit descriptors are not implemented");
        case SQL_ATTR_FETCH_BOOKMARK_PTR:
            return cs_diag_add(&s->h,"HYC00",0,"Bookmarks are not supported");
        case SQL_ATTR_ROW_NUMBER:
            return cs_diag_add(&s->h,"HY092",0,"Statement attribute %ld is read-only",(long)attribute);
        default:return cs_diag_add(&s->h,"HYC00",0,"Statement attribute %ld is not supported",(long)attribute);
    }
}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetStmtAttr(SQLHSTMT statement,SQLINTEGER attribute,
    SQLPOINTER value,SQLINTEGER length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetStmtAttr(statement, attribute, value, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetStmtAttr(SQLHSTMT statement,SQLINTEGER attribute,
    SQLPOINTER value,SQLINTEGER capacity,SQLINTEGER *length){
    cs_stmt *s=(cs_stmt *)statement; SQLULEN v; (void)capacity;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE; cs_diag_clear(&s->h);
    switch(attribute){
        case SQL_ATTR_QUERY_TIMEOUT:v=s->query_timeout;break;case SQL_ATTR_MAX_ROWS:v=s->max_rows;break;
        case SQL_ATTR_MAX_LENGTH:v=s->max_length;break;
        case SQL_ROWSET_SIZE:case SQL_ATTR_ROW_ARRAY_SIZE:v=s->row_array_size;break;
        case SQL_ATTR_ROWS_FETCHED_PTR:if(value)*(SQLULEN **)value=s->rows_fetched;if(length)*length=sizeof(void *);return SQL_SUCCESS;
        case SQL_ATTR_ROW_STATUS_PTR:if(value)*(SQLUSMALLINT **)value=s->row_status;if(length)*length=sizeof(void *);return SQL_SUCCESS;
        case SQL_ATTR_ROW_OPERATION_PTR:if(value)*(SQLUSMALLINT **)value=s->row_operation;if(length)*length=sizeof(void *);return SQL_SUCCESS;
        case SQL_ATTR_ROW_BIND_OFFSET_PTR:if(value)*(SQLULEN **)value=s->row_bind_offset;if(length)*length=sizeof(void *);return SQL_SUCCESS;
        case SQL_ATTR_PARAMSET_SIZE:v=s->paramset_size;break;
        case SQL_ATTR_PARAMS_PROCESSED_PTR:if(value)*(SQLULEN **)value=s->params_processed;if(length)*length=sizeof(void *);return SQL_SUCCESS;
        case SQL_ATTR_PARAM_STATUS_PTR:if(value)*(SQLUSMALLINT **)value=s->param_status;if(length)*length=sizeof(void *);return SQL_SUCCESS;
        case SQL_ATTR_PARAM_OPERATION_PTR:if(value)*(SQLUSMALLINT **)value=s->param_operation;if(length)*length=sizeof(void *);return SQL_SUCCESS;
        case SQL_ATTR_PARAM_BIND_OFFSET_PTR:if(value)*(SQLULEN **)value=s->param_bind_offset;if(length)*length=sizeof(void *);return SQL_SUCCESS;
        case SQL_ATTR_CURSOR_TYPE:v=s->cursor_type;break;case SQL_ATTR_CONCURRENCY:v=s->concurrency;break;
        case SQL_ATTR_RETRIEVE_DATA:v=s->retrieve_data;break;case SQL_ATTR_ROW_BIND_TYPE:v=s->row_bind_type;break;
        case SQL_ATTR_PARAM_BIND_TYPE:v=s->param_bind_type;break;case SQL_ATTR_USE_BOOKMARKS:v=s->use_bookmarks;break;
        case SQL_ATTR_NOSCAN:v=s->noscan;break;case SQL_ATTR_METADATA_ID:v=s->metadata_id;break;
        case SQL_ATTR_ASYNC_ENABLE:v=s->async_enable;break;
        case SQL_ATTR_CURSOR_SCROLLABLE:v=s->cursor_scrollable;break;
        case SQL_ATTR_CURSOR_SENSITIVITY:v=s->cursor_sensitivity;break;
        case SQL_ATTR_KEYSET_SIZE:v=s->keyset_size;break;
        case SQL_ATTR_SIMULATE_CURSOR:v=s->simulate_cursor;break;
        case SQL_ATTR_ENABLE_AUTO_IPD:v=SQL_FALSE;break;
        case SQL_ATTR_ROW_NUMBER:v=(SQLULEN)(s->current_row>0?s->current_row:0);break;
        case SQL_ATTR_APP_ROW_DESC:case SQL_ATTR_APP_PARAM_DESC:
        case SQL_ATTR_IMP_ROW_DESC:case SQL_ATTR_IMP_PARAM_DESC:
            return cs_diag_add(&s->h,"HYC00",0,"Explicit descriptors are not implemented");
        default:return cs_diag_add(&s->h,"HY092",0,"Invalid statement attribute %ld",(long)attribute);
    }
    if(value)*(SQLULEN *)value=v;if(length)*length=sizeof(SQLULEN);return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetStmtAttr(SQLHSTMT statement,SQLINTEGER attribute,
    SQLPOINTER value,SQLINTEGER capacity,SQLINTEGER *length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetStmtAttr(statement, attribute, value, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

/*
 * SQLSetScrollOptions e' l'ultima funzione ODBC 2.0 che mancava: e' Level 2,
 * quindi facoltativa per un driver che dichiara Level 1 come questo, ma era
 * l'unico buco nell'intera API 2.0 e chiuderlo costa poco. E' deprecata in
 * ODBC 3.x, dove il suo lavoro si fa con SQL_ATTR_CURSOR_TYPE,
 * SQL_ATTR_CONCURRENCY e SQL_ATTR_ROW_ARRAY_SIZE: qui si limita a tradurre nei
 * tre attributi, cosi' la sostituzione dei tipi di cursore non supportati e la
 * relativa segnalazione 01S02 restano in un punto solo.
 */
static SQLRETURN SQL_API cs_i_SQLSetScrollOptions(SQLHSTMT statement,SQLUSMALLINT concurrency,
    SQLLEN keyset,SQLUSMALLINT rowset){
    cs_stmt *s=(cs_stmt *)statement;SQLULEN cursor_type;SQLRETURN rc,worst=SQL_SUCCESS;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;
    cs_diag_clear(&s->h);
    if(rowset<1)return cs_diag_add(&s->h,"HY107",0,"Row value out of range");
    switch(keyset){
        case SQL_SCROLL_FORWARD_ONLY:cursor_type=SQL_CURSOR_FORWARD_ONLY;break;
        case SQL_SCROLL_STATIC:cursor_type=SQL_CURSOR_STATIC;break;
        case SQL_SCROLL_KEYSET_DRIVEN:cursor_type=SQL_CURSOR_KEYSET_DRIVEN;break;
        case SQL_SCROLL_DYNAMIC:cursor_type=SQL_CURSOR_DYNAMIC;break;
        default:
            if(keyset<1)return cs_diag_add(&s->h,"HY107",0,"Row value out of range");
            if(keyset<(SQLLEN)rowset)return cs_diag_add(&s->h,"HY107",0,"Keyset size must be at least the rowset size");
            cursor_type=SQL_CURSOR_KEYSET_DRIVEN;
            rc=SQLSetStmtAttr(statement,SQL_ATTR_KEYSET_SIZE,(SQLPOINTER)(SQLULEN)keyset,0);
            if(!SQL_SUCCEEDED(rc))return rc;
            if(rc==SQL_SUCCESS_WITH_INFO)worst=rc;
            break;
    }
    rc=SQLSetStmtAttr(statement,SQL_ATTR_CURSOR_TYPE,(SQLPOINTER)cursor_type,0);
    if(!SQL_SUCCEEDED(rc))return rc; if(rc==SQL_SUCCESS_WITH_INFO)worst=rc;
    rc=SQLSetStmtAttr(statement,SQL_ATTR_CONCURRENCY,(SQLPOINTER)(SQLULEN)concurrency,0);
    if(!SQL_SUCCEEDED(rc))return rc; if(rc==SQL_SUCCESS_WITH_INFO)worst=rc;
    rc=SQLSetStmtAttr(statement,SQL_ATTR_ROW_ARRAY_SIZE,(SQLPOINTER)(SQLULEN)rowset,0);
    if(!SQL_SUCCEEDED(rc))return rc; if(rc==SQL_SUCCESS_WITH_INFO)worst=rc;
    return worst;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetScrollOptions(SQLHSTMT statement,SQLUSMALLINT concurrency,
    SQLLEN keyset,SQLUSMALLINT rowset) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetScrollOptions(statement, concurrency, keyset, rowset);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLSetStmtOption(SQLHSTMT s,SQLUSMALLINT a,SQLULEN v){return SQLSetStmtAttr(s,a,(SQLPOINTER)(uintptr_t)v,0);}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetStmtOption(SQLHSTMT s,SQLUSMALLINT a,SQLULEN v) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetStmtOption(s, a, v);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLGetStmtOption(SQLHSTMT s,SQLUSMALLINT a,SQLPOINTER v){return SQLGetStmtAttr(s,a,v,0,NULL);}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetStmtOption(SQLHSTMT s,SQLUSMALLINT a,SQLPOINTER v) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetStmtOption(s, a, v);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static const char *cs_skip_sql_space(const char *p){
    for(;;){
        while(*p&&isspace((unsigned char)*p))++p;
        if(p[0]=='-'&&p[1]=='-'){p+=2;while(*p&&*p!='\n')++p;continue;}
        if(p[0]=='/'&&p[1]=='*'){p+=2;while(*p&&!(p[0]=='*'&&p[1]=='/'))++p;if(*p)p+=2;continue;}
        return p;
    }
}

static void cs_first_token(const char *sql,char *token,size_t cap){
    const char *p=cs_skip_sql_space(sql?sql:"");size_t n=0;
    while(*p&&(isalpha((unsigned char)*p)||*p=='_')){if(n+1<cap)token[n++]=(char)toupper((unsigned char)*p);++p;}token[n]='\0';
}

static int cs_sql_returns_rows(const char *sql){
    char token[32];cs_first_token(sql,token,sizeof(token));
    /* SHOW is a CubeSQL command that produces a cursor like a SELECT does. */
    return !strcmp(token,"SELECT")||!strcmp(token,"PRAGMA")||!strcmp(token,"EXPLAIN")||
           !strcmp(token,"VALUES")||!strcmp(token,"WITH")||!strcmp(token,"SHOW");
}

static int cs_sql_is_write(const char *sql){
    char token[32];cs_first_token(sql,token,sizeof(token));
    return !strcmp(token,"INSERT")||!strcmp(token,"UPDATE")||!strcmp(token,"DELETE")||!strcmp(token,"REPLACE")||
           !strcmp(token,"CREATE")||!strcmp(token,"DROP")||!strcmp(token,"ALTER")||!strcmp(token,"VACUUM")||!strcmp(token,"REINDEX")||!strcmp(token,"ATTACH")||!strcmp(token,"DETACH");
}

static int cs_sql_should_commit(const char *sql){
    const char *p=cs_skip_sql_space(sql?sql:"");char first[32],second[32];size_t n=0;
    while(*p&&(isalpha((unsigned char)*p)||*p=='_')){if(n+1<sizeof(first))first[n++]=(char)toupper((unsigned char)*p);++p;}first[n]='\0';
    p=cs_skip_sql_space(p);n=0;while(*p&&(isalpha((unsigned char)*p)||*p=='_')){if(n+1<sizeof(second))second[n++]=(char)toupper((unsigned char)*p);++p;}second[n]='\0';
    if((!strcmp(first,"CREATE")||!strcmp(first,"DROP"))&&!strcmp(second,"DATABASE"))return 0;
    return cs_sql_is_write(sql);
}

/*
 * Recognises "USE DATABASE <name>" and hands back the name.
 *
 * The driver has to know which database the connection is on: it is what
 * SQLTables reports as TABLE_CAT, and what SQLGetInfo answers for
 * SQL_DATABASE_NAME. Connecting with DATABASE= set it, but selecting the
 * database by statement - which is the documented way to do it, and what the
 * test suite itself does - left the driver believing it had none. Catalog
 * metadata then came back with an empty TABLE_CAT, so a consumer could not tell
 * which database a table belonged to.
 *
 * Returns 1 and fills name when the statement is a USE DATABASE, 0 otherwise.
 */
static int cs_sql_use_database(const char *sql, char *name, size_t cap) {
    const char *p = cs_skip_sql_space(sql ? sql : "");
    char word[32];
    size_t n = 0;
    while (*p && (isalpha((unsigned char)*p) || *p == '_')) {
        if (n + 1 < sizeof(word)) word[n++] = (char)toupper((unsigned char)*p);
        ++p;
    }
    word[n] = '\0';
    if (strcmp(word, "USE")) return 0;
    p = cs_skip_sql_space(p); n = 0;
    while (*p && (isalpha((unsigned char)*p) || *p == '_')) {
        if (n + 1 < sizeof(word)) word[n++] = (char)toupper((unsigned char)*p);
        ++p;
    }
    word[n] = '\0';
    if (strcmp(word, "DATABASE")) return 0;
    p = cs_skip_sql_space(p); n = 0;
    if (*p == '\'' || *p == '"' || *p == '[') {
        char closing = (*p == '[') ? ']' : *p;
        ++p;
        while (*p && *p != closing) { if (n + 1 < cap) name[n++] = *p; ++p; }
    } else {
        while (*p && !isspace((unsigned char)*p) && *p != ';') {
            if (n + 1 < cap) name[n++] = *p;
            ++p;
        }
    }
    if (cap) name[n] = '\0';
    return n > 0;
}


/*
 * ODBC escape sequence translation.
 *
 * Applications such as Access and Excel emit {ts '...'} literals and {fn ...}
 * scalar calls constantly. Without translation those reach CubeSQL verbatim and
 * fail, so SQLGetInfo may only advertise the functions handled here.
 *
 * Only functions that map onto a SQLite builtin by rename are advertised, which
 * keeps the translation a name substitution: nothing needs to reorder or
 * reinterpret arguments, so it cannot corrupt a query.
 */
static const struct { const char *odbc; const char *native; } cs_fn_map[] = {
    {"ASCII","unicode"}, {"CHAR","char"}, {"LCASE","lower"}, {"LENGTH","length"},
    {"LTRIM","ltrim"}, {"REPLACE","replace"}, {"RTRIM","rtrim"}, {"SUBSTRING","substr"},
    {"UCASE","upper"}, {"ABS","abs"}, {"ROUND","round"}, {"IFNULL","ifnull"},
};

/* No-argument forms that need a literal rewrite rather than a rename. */
static const struct { const char *odbc; const char *native; } cs_fn0_map[] = {
    {"CURDATE","date('now')"}, {"CURTIME","time('now')"}, {"CURRENT_DATE","date('now')"},
    {"CURRENT_TIME","time('now')"}, {"NOW","datetime('now')"}, {"CURRENT_TIMESTAMP","datetime('now')"},
};

struct cs_sqlbuf { char *data; size_t len, cap; };

static int cs_buf_add(struct cs_sqlbuf *b, const char *text, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 256;
        char *p;
        while (cap < b->len + n + 1) cap *= 2;
        p = (char *)realloc(b->data, cap);
        if (!p) return 0;
        b->data = p; b->cap = cap;
    }
    memcpy(b->data + b->len, text, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 1;
}

static int cs_word_equal(const char *p, size_t n, const char *word) {
    size_t i;
    if (strlen(word) != n) return 0;
    for (i = 0; i < n; i++)
        if (toupper((unsigned char)p[i]) != toupper((unsigned char)word[i])) return 0;
    return 1;
}

/*
 * Rewrites ODBC escape sequences into CubeSQL syntax. Returns a newly allocated
 * string, or NULL on allocation failure. Quoted text and comments pass through
 * untouched.
 */
static char *cs_translate_escapes(const char *sql) {
    struct cs_sqlbuf out;
    const char *p = sql ? sql : "";
    int depth = 0;                  /* open ODBC escapes awaiting their '}' */
    memset(&out, 0, sizeof(out));
    if (!cs_buf_add(&out, "", 0)) return NULL;
    while (*p) {
        /* string literals and quoted identifiers */
        if (*p == '\'' || *p == '"' || *p == '`') {
            char q = *p;
            const char *start = p++;
            while (*p) {
                if (*p == q) { if (p[1] == q) p += 2; else { p++; break; } }
                else p++;
            }
            if (!cs_buf_add(&out, start, (size_t)(p - start))) goto fail;
            continue;
        }
        if (*p == '[') {
            const char *start = p++;
            while (*p && *p != ']') p++;
            if (*p) p++;
            if (!cs_buf_add(&out, start, (size_t)(p - start))) goto fail;
            continue;
        }
        if (p[0] == '-' && p[1] == '-') {
            const char *start = p;
            while (*p && *p != '\n') p++;
            if (!cs_buf_add(&out, start, (size_t)(p - start))) goto fail;
            continue;
        }
        if (p[0] == '/' && p[1] == '*') {
            const char *start = p;
            p += 2;
            while (*p && !(p[0] == '*' && p[1] == '/')) p++;
            if (*p) p += 2;
            if (!cs_buf_add(&out, start, (size_t)(p - start))) goto fail;
            continue;
        }
        if (*p == '}' && depth > 0) { depth--; p++; continue; }
        if (*p == '{') {
            const char *scan = p + 1, *word;
            size_t wlen;
            while (*scan && isspace((unsigned char)*scan)) scan++;
            word = scan;
            while (*scan && (isalpha((unsigned char)*scan) || *scan == '_')) scan++;
            wlen = (size_t)(scan - word);
            /* {d '...'} {t '...'} {ts '...'}: keep just the literal */
            if (cs_word_equal(word, wlen, "d") || cs_word_equal(word, wlen, "t") ||
                cs_word_equal(word, wlen, "ts")) {
                depth++; p = scan; continue;
            }
            /* {oj <join>}: CubeSQL understands the join on its own */
            if (cs_word_equal(word, wlen, "oj")) { depth++; p = scan; continue; }
            /* {escape 'c'} -> ESCAPE 'c' */
            if (cs_word_equal(word, wlen, "escape")) {
                if (!cs_buf_add(&out, " ESCAPE ", 8)) goto fail;
                depth++; p = scan; continue;
            }
            if (cs_word_equal(word, wlen, "fn")) {
                const char *fn;
                size_t flen, i;
                while (*scan && isspace((unsigned char)*scan)) scan++;
                fn = scan;
                while (*scan && (isalnum((unsigned char)*scan) || *scan == '_')) scan++;
                flen = (size_t)(scan - fn);
                for (i = 0; i < sizeof(cs_fn0_map) / sizeof(cs_fn0_map[0]); i++) {
                    if (!cs_word_equal(fn, flen, cs_fn0_map[i].odbc)) continue;
                    /* only the zero-argument form is rewritten to a literal */
                    {
                        const char *after = scan;
                        while (*after && isspace((unsigned char)*after)) after++;
                        if (after[0] == '(') {
                            const char *close = after + 1;
                            while (*close && isspace((unsigned char)*close)) close++;
                            if (*close == ')') {
                                if (!cs_buf_add(&out, cs_fn0_map[i].native,
                                                strlen(cs_fn0_map[i].native))) goto fail;
                                depth++; p = close + 1; goto next;
                            }
                        }
                    }
                }
                for (i = 0; i < sizeof(cs_fn_map) / sizeof(cs_fn_map[0]); i++) {
                    if (!cs_word_equal(fn, flen, cs_fn_map[i].odbc)) continue;
                    if (!cs_buf_add(&out, cs_fn_map[i].native, strlen(cs_fn_map[i].native))) goto fail;
                    depth++; p = scan; goto next;
                }
                /* Unknown function: pass the name through and let the server rule. */
                if (!cs_buf_add(&out, fn, flen)) goto fail;
                depth++; p = scan; continue;
            }
            /* Anything else ({call ...}, vendor escapes): drop the braces only. */
            depth++; p = scan; continue;
        }
        if (!cs_buf_add(&out, p, 1)) goto fail;
        p++;
    next:
        continue;
    }
    return out.data;
fail:
    free(out.data);
    return NULL;
}

static SQLUSMALLINT cs_count_parameters(const char *sql){
    SQLUSMALLINT n=0;int quote=0,line=0,block=0;const unsigned char *p=(const unsigned char *)sql;
    while(p&&*p){
        if(line){if(*p=='\n')line=0;++p;continue;}if(block){if(p[0]=='*'&&p[1]=='/'){block=0;p+=2;}else ++p;continue;}
        if(!quote&&p[0]=='-'&&p[1]=='-'){line=1;p+=2;continue;}if(!quote&&p[0]=='/'&&p[1]=='*'){block=1;p+=2;continue;}
        if(quote){if(*p==quote){if(p[1]==quote){p+=2;continue;}quote=0;}++p;continue;}
        if(*p=='\''||*p=='"'||*p=='`'){quote=*p++;continue;}if(*p=='['){quote=']';++p;continue;}
        if(*p=='?'){if(n<CSODBC_MAX_PARAMS)n++;}++p;
    }return n;
}

static SQLRETURN SQL_API cs_i_SQLPrepare(SQLHSTMT statement,SQLCHAR *text,SQLINTEGER length){
    cs_stmt *s=(cs_stmt *)statement;char *sql;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);cs_stmt_close(s);
    if(!text)return cs_diag_add(&s->h,"HY009",0,"SQL text is null");
    sql=cs_strndup0((const char *)text,cs_input_len(text,length));if(!sql)return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");
    /* SQL_ATTR_NOSCAN lets an application say its SQL holds no ODBC escapes. */
    if(s->noscan==SQL_NOSCAN_OFF&&strchr(sql,'{')){
        char *translated=cs_translate_escapes(sql);
        if(!translated){free(sql);return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");}
        free(sql);sql=translated;
    }
    free(s->sql);s->sql=sql;s->num_params=cs_count_parameters(sql);s->prepared=1;return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLPrepare(SQLHSTMT statement,SQLCHAR *text,SQLINTEGER length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLPrepare(statement, text, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLPrepareW(SQLHSTMT statement,SQLWCHAR *text,SQLINTEGER length){char *u=cs_utf16_to_utf8(text,length);SQLRETURN rc;if(!u)return SQL_ERROR;rc=SQLPrepare(statement,(SQLCHAR *)u,SQL_NTS);free(u);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLPrepareW(SQLHSTMT statement,SQLWCHAR *text,SQLINTEGER length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLPrepareW(statement, text, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLPrepareA(SQLHSTMT s,SQLCHAR *t,SQLINTEGER n){return SQLPrepare(s,t,n);}

CSODBC_EXPORT SQLRETURN SQL_API SQLPrepareA(SQLHSTMT s,SQLCHAR *t,SQLINTEGER n) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLPrepareA(s, t, n);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLNumParams(SQLHSTMT statement,SQLSMALLINT *count){
    cs_stmt *s=(cs_stmt *)statement;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);
    if(!s->prepared)return cs_diag_add(&s->h,"HY010",0,"Statement is not prepared");if(count)*count=(SQLSMALLINT)s->num_params;return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLNumParams(SQLHSTMT statement,SQLSMALLINT *count) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLNumParams(statement, count);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLBindParameter(SQLHSTMT statement,SQLUSMALLINT number,
    SQLSMALLINT io_type,SQLSMALLINT c_type,SQLSMALLINT sql_type,SQLULEN column_size,
    SQLSMALLINT scale,SQLPOINTER value,SQLLEN buffer_length,SQLLEN *indicator){
    cs_stmt *s=(cs_stmt *)statement;cs_param_binding *p;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);
    if(number<1||number>CSODBC_MAX_PARAMS||(s->prepared&&number>s->num_params))return cs_diag_add(&s->h,"07009",0,"Invalid parameter number");
    if(io_type!=SQL_PARAM_INPUT)return cs_diag_add(&s->h,"HYC00",0,"Only input parameters are supported");
    p=&s->params[number-1];free(p->at_exec);memset(p,0,sizeof(*p));
    p->io_type=io_type;p->c_type=c_type;p->sql_type=sql_type;p->column_size=column_size;p->scale=scale;p->value=value;p->buffer_length=buffer_length;p->indicator=indicator;
    if(number>s->num_params)s->num_params=number;return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLBindParameter(SQLHSTMT statement,SQLUSMALLINT number,
    SQLSMALLINT io_type,SQLSMALLINT c_type,SQLSMALLINT sql_type,SQLULEN column_size,
    SQLSMALLINT scale,SQLPOINTER value,SQLLEN buffer_length,SQLLEN *indicator) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLBindParameter(statement, number, io_type, c_type, sql_type, column_size, scale, value, buffer_length, indicator);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLBindParam(SQLHSTMT s,SQLUSMALLINT n,SQLSMALLINT ct,SQLSMALLINT st,SQLULEN z,SQLSMALLINT sc,SQLPOINTER v,SQLLEN *i){return SQLBindParameter(s,n,SQL_PARAM_INPUT,ct,st,z,sc,v,0,i);}

CSODBC_EXPORT SQLRETURN SQL_API SQLBindParam(SQLHSTMT s,SQLUSMALLINT n,SQLSMALLINT ct,SQLSMALLINT st,SQLULEN z,SQLSMALLINT sc,SQLPOINTER v,SQLLEN *i) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLBindParam(s, n, ct, st, z, sc, v, i);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLSetParam(SQLHSTMT s,SQLUSMALLINT n,SQLSMALLINT ct,SQLSMALLINT st,SQLULEN z,SQLSMALLINT sc,SQLPOINTER v,SQLLEN *i){return SQLBindParam(s,n,ct,st,z,sc,v,i);}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetParam(SQLHSTMT s,SQLUSMALLINT n,SQLSMALLINT ct,SQLSMALLINT st,SQLULEN z,SQLSMALLINT sc,SQLPOINTER v,SQLLEN *i) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetParam(s, n, ct, st, z, sc, v, i);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLDescribeParam(SQLHSTMT statement,SQLUSMALLINT number,
    SQLSMALLINT *type,SQLULEN *size,SQLSMALLINT *scale,SQLSMALLINT *nullable){
    cs_stmt *s=(cs_stmt *)statement;cs_param_binding *p;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);
    if(number<1||number>s->num_params)return cs_diag_add(&s->h,"07009",0,"Invalid parameter number");p=&s->params[number-1];
    if(type)*type=p->sql_type?p->sql_type:SQL_VARCHAR;if(size)*size=p->column_size?p->column_size:65535;if(scale)*scale=p->scale;if(nullable)*nullable=SQL_NULLABLE_UNKNOWN;return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLDescribeParam(SQLHSTMT statement,SQLUSMALLINT number,
    SQLSMALLINT *type,SQLULEN *size,SQLSMALLINT *scale,SQLSMALLINT *nullable) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLDescribeParam(statement, number, type, size, scale, nullable);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLSMALLINT cs_default_c_type(SQLSMALLINT sql_type){
    switch(sql_type){case SQL_SMALLINT:return SQL_C_SHORT;case SQL_INTEGER:return SQL_C_LONG;case SQL_BIGINT:return SQL_C_SBIGINT;
        case SQL_REAL:return SQL_C_FLOAT;case SQL_FLOAT:case SQL_DOUBLE:case SQL_NUMERIC:case SQL_DECIMAL:return SQL_C_DOUBLE;
        case SQL_BINARY:case SQL_VARBINARY:case SQL_LONGVARBINARY:return SQL_C_BINARY;case SQL_BIT:return SQL_C_BIT;
        case SQL_TYPE_DATE:return SQL_C_TYPE_DATE;case SQL_TYPE_TIME:return SQL_C_TYPE_TIME;case SQL_TYPE_TIMESTAMP:return SQL_C_TYPE_TIMESTAMP;default:return SQL_C_CHAR;}
}

static SQLLEN cs_ctype_stride(SQLSMALLINT c_type,SQLLEN buffer_length);

/* Parameter arrays use the same column-wise / row-wise layout as rowsets. */
static SQLPOINTER cs_param_addr(cs_stmt *s,cs_param_binding *p,SQLULEN set){
    char *q=(char *)p->value;
    if(!q)return NULL;
    if(s->param_bind_offset)q+=*s->param_bind_offset;
    if(s->param_bind_type==SQL_BIND_BY_COLUMN)q+=(SQLLEN)set*cs_ctype_stride(p->c_type,p->buffer_length);
    else q+=(SQLLEN)set*(SQLLEN)s->param_bind_type;
    return (SQLPOINTER)q;
}

static SQLLEN *cs_param_ind(cs_stmt *s,cs_param_binding *p,SQLULEN set){
    char *q=(char *)p->indicator;
    if(!q)return NULL;
    if(s->param_bind_offset)q+=*s->param_bind_offset;
    if(s->param_bind_type==SQL_BIND_BY_COLUMN)q+=(SQLLEN)set*(SQLLEN)sizeof(SQLLEN);
    else q+=(SQLLEN)set*(SQLLEN)s->param_bind_type;
    return (SQLLEN *)q;
}

static int cs_vm_bind(cs_stmt *s,csqlvm *vm,SQLUSMALLINT index,SQLULEN set){
    cs_param_binding *p=&s->params[index-1];SQLLEN *ind=cs_param_ind(s,p,set);
    SQLLEN len=ind?*ind:p->buffer_length;SQLSMALLINT ct=p->c_type==SQL_C_DEFAULT?cs_default_c_type(p->sql_type):p->c_type;char tmp[128];char *u;int rc;
    const void *data=cs_param_addr(s,p,set);
    if(p->at_exec_len==SQL_NULL_DATA)return cubesql_vmbind_null(vm,index);
    if(p->at_exec){data=p->at_exec;len=p->at_exec_len;ct=(p->sql_type==SQL_BINARY||p->sql_type==SQL_VARBINARY||p->sql_type==SQL_LONGVARBINARY)?SQL_C_BINARY:SQL_C_CHAR;}
    if(len==SQL_NULL_DATA)return cubesql_vmbind_null(vm,index);
    if(!data)return cubesql_vmbind_null(vm,index);
    switch(ct){
        case SQL_C_CHAR:
            if(len==SQL_NTS||len<0)len=(SQLLEN)strlen((const char *)data);
            if(s->dbc->ansi_charset){
                size_t converted=0;
                char *utf8=cs_ansi_to_utf8((const char *)data,(size_t)len,&converted);
                if(!utf8)return CUBESQL_MEMORY_ERROR;
                rc=cubesql_vmbind_text(vm,index,utf8,(int)converted);
                free(utf8);
                return rc;
            }
            return cubesql_vmbind_text(vm,index,(char *)data,(int)len);
        case SQL_C_WCHAR:u=cs_utf16_to_utf8((const SQLWCHAR *)data,len==SQL_NTS?SQL_NTS:(SQLINTEGER)(len/sizeof(SQLWCHAR)));if(!u)return CUBESQL_MEMORY_ERROR;rc=cubesql_vmbind_text(vm,index,u,(int)strlen(u));free(u);return rc;
        case SQL_C_BINARY:return cubesql_vmbind_blob(vm,index,(void *)data,(int)(len>=0?len:p->buffer_length));
        case SQL_C_SHORT:case SQL_C_SSHORT:return cubesql_vmbind_int(vm,index,*(const int16_t *)data);
        case SQL_C_USHORT:return cubesql_vmbind_int(vm,index,*(const uint16_t *)data);
        case SQL_C_LONG:case SQL_C_SLONG:return cubesql_vmbind_int(vm,index,*(const int32_t *)data);
        case SQL_C_ULONG:return cubesql_vmbind_int64(vm,index,*(const uint32_t *)data);
        case SQL_C_SBIGINT:return cubesql_vmbind_int64(vm,index,*(const int64_t *)data);
        case SQL_C_UBIGINT:snprintf(tmp,sizeof(tmp),"%llu",(unsigned long long)*(const uint64_t *)data);return cubesql_vmbind_text(vm,index,tmp,(int)strlen(tmp));
        case SQL_C_FLOAT:return cubesql_vmbind_double(vm,index,*(const float *)data);case SQL_C_DOUBLE:return cubesql_vmbind_double(vm,index,*(const double *)data);
        case SQL_C_BIT:return cubesql_vmbind_int(vm,index,*(const unsigned char *)data?1:0);
        case SQL_C_DATE:case SQL_C_TYPE_DATE:{const SQL_DATE_STRUCT *d=(const SQL_DATE_STRUCT *)data;snprintf(tmp,sizeof(tmp),"%04d-%02u-%02u",d->year,d->month,d->day);break;}
        case SQL_C_TIME:case SQL_C_TYPE_TIME:{const SQL_TIME_STRUCT *t=(const SQL_TIME_STRUCT *)data;snprintf(tmp,sizeof(tmp),"%02u:%02u:%02u",t->hour,t->minute,t->second);break;}
        case SQL_C_TIMESTAMP:case SQL_C_TYPE_TIMESTAMP:{const SQL_TIMESTAMP_STRUCT *t=(const SQL_TIMESTAMP_STRUCT *)data;snprintf(tmp,sizeof(tmp),"%04d-%02u-%02u %02u:%02u:%02u.%09lu",t->year,t->month,t->day,t->hour,t->minute,t->second,(unsigned long)t->fraction);break;}
        default:return CUBESQL_PARAMETER_ERROR;
    }return cubesql_vmbind_text(vm,index,tmp,(int)strlen(tmp));
}

static int cs_param_needs_data(cs_param_binding *p){SQLLEN n=p->indicator?*p->indicator:0;return n==SQL_DATA_AT_EXEC||n<=SQL_LEN_DATA_AT_EXEC_OFFSET;}

/* Runs one prepared statement once per bound parameter set. */
static SQLRETURN cs_execute_paramsets(cs_stmt *s,csqlvm *vm,SQLULEN sets){
    SQLULEN set,processed=0,failed=0;SQLLEN affected=0;SQLRETURN overall=SQL_SUCCESS;
    for(set=0;set<sets;set++){
        SQLUSMALLINT i;int rc;
        if(s->param_operation&&s->param_operation[set]==SQL_PARAM_IGNORE){
            if(s->param_status)s->param_status[set]=SQL_PARAM_UNUSED;
            continue;
        }
        for(i=1;i<=s->num_params;i++){
            rc=cs_vm_bind(s,vm,i,set);
            if(rc!=CUBESQL_NOERR){cs_map_sdk_error(&s->h,s->dbc->db,rc,"bind parameter");goto set_failed;}
        }
        rc=cubesql_vmexecute(vm);
        if(rc!=CUBESQL_NOERR){cs_map_sdk_error(&s->h,s->dbc->db,rc,"execute");goto set_failed;}
        affected+=(SQLLEN)cubesql_affected_rows(s->dbc->db);
        processed++;
        if(s->param_status)s->param_status[set]=SQL_PARAM_SUCCESS;
        continue;
    set_failed:
        failed++;processed++;
        if(s->param_status)s->param_status[set]=SQL_PARAM_ERROR;
        overall=SQL_SUCCESS_WITH_INFO;
    }
    if(s->params_processed)*s->params_processed=processed;
    s->row_count=affected;
    if(failed&&failed==processed)return SQL_ERROR;
    return overall;
}

static SQLRETURN cs_execute_now(cs_stmt *s){
    csqlvm *vm;SQLUSMALLINT i;int rc;SQLULEN sets;
    if(!s->dbc->connected)return cs_diag_add(&s->h,"08003",0,"Connection is not open");
    if(s->dbc->access_mode==SQL_MODE_READ_ONLY&&cs_sql_is_write(s->sql))return cs_diag_add(&s->h,"25006",0,"Connection is read-only");
    if(s->num_params==0){
        if(cs_sql_returns_rows(s->sql)){
            s->cursor=cubesql_select(s->dbc->db,s->sql,kFALSE);
            if(!s->cursor){
                cs_map_sdk_error(&s->h,s->dbc->db,cubesql_errcode(s->dbc->db),"execute query");
                return SQL_ERROR;}
            s->row_count=-1;
        }else{
            rc=cubesql_execute(s->dbc->db,s->sql);
            if(rc!=CUBESQL_NOERR){cs_map_sdk_error(&s->h,s->dbc->db,rc,"execute");return SQL_ERROR;}
            {   /* la connessione ha appena cambiato database: aggiornalo, o il
                   catalogo riportato resta quello di prima */
                char picked[sizeof(s->dbc->database)];
                if(cs_sql_use_database(s->sql,picked,sizeof(picked)))
                    cs_option_set(s->dbc->database,sizeof(s->dbc->database),picked);
            }
            s->row_count=(SQLLEN)cubesql_affected_rows(s->dbc->db);
            if(s->dbc->autocommit==SQL_AUTOCOMMIT_ON&&cs_sql_should_commit(s->sql)){rc=cubesql_commit(s->dbc->db);if(rc!=CUBESQL_NOERR){cs_map_sdk_error(&s->h,s->dbc->db,rc,"autocommit");return SQL_ERROR;}}
        }
        s->executed=1;if(s->params_processed)*s->params_processed=1;if(s->param_status)s->param_status[0]=SQL_PARAM_SUCCESS;return SQL_SUCCESS;
    }
    sets=s->paramset_size?s->paramset_size:1;
    if(sets>1&&cs_sql_returns_rows(s->sql))
        return cs_diag_add(&s->h,"HYC00",0,"Parameter arrays cannot be used with result-set statements");
    vm=cubesql_vmprepare(s->dbc->db,s->sql);if(!vm){cs_map_sdk_error(&s->h,s->dbc->db,cubesql_errcode(s->dbc->db),"prepare");return SQL_ERROR;}
    if(cs_sql_returns_rows(s->sql)){
        for(i=1;i<=s->num_params;i++){rc=cs_vm_bind(s,vm,i,0);if(rc!=CUBESQL_NOERR){cubesql_vmclose(vm);cs_map_sdk_error(&s->h,s->dbc->db,rc,"bind parameter");return SQL_ERROR;}}
        s->cursor=cubesql_vmselect(vm);
        if(!s->cursor){cubesql_vmclose(vm);cs_map_sdk_error(&s->h,s->dbc->db,cubesql_errcode(s->dbc->db),"execute query");return SQL_ERROR;}
        s->row_count=-1;
        if(s->params_processed)*s->params_processed=1;
        if(s->param_status)s->param_status[0]=SQL_PARAM_SUCCESS;
    }else{
        SQLRETURN exec_rc=cs_execute_paramsets(s,vm,sets);
        if(exec_rc==SQL_ERROR){cubesql_vmclose(vm);return SQL_ERROR;}
        if(s->dbc->autocommit==SQL_AUTOCOMMIT_ON&&cs_sql_should_commit(s->sql)){
            rc=cubesql_commit(s->dbc->db);
            if(rc!=CUBESQL_NOERR){cubesql_vmclose(vm);cs_map_sdk_error(&s->h,s->dbc->db,rc,"autocommit");return SQL_ERROR;}
        }
        cubesql_vmclose(vm);s->executed=1;return exec_rc;
    }
    cubesql_vmclose(vm);s->executed=1;return SQL_SUCCESS;
}

static SQLRETURN SQL_API cs_i_SQLExecute(SQLHSTMT statement){
    cs_stmt *s=(cs_stmt *)statement;SQLUSMALLINT i;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);cs_stmt_close(s);
    if(!s->prepared||!s->sql)return cs_diag_add(&s->h,"HY010",0,"Statement is not prepared");
    for(i=1;i<=s->num_params;i++)if(!s->params[i-1].io_type)return cs_diag_add(&s->h,"07002",0,"Parameter %u is not bound",i);
    for(i=1;i<=s->num_params;i++)if(cs_param_needs_data(&s->params[i-1])){s->at_exec_param=0;s->need_data_active=1;return SQL_NEED_DATA;}
    return cs_execute_now(s);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLExecute(SQLHSTMT statement) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLExecute(statement);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLExecDirect(SQLHSTMT statement,SQLCHAR *text,SQLINTEGER length){SQLRETURN rc=SQLPrepare(statement,text,length);return SQL_SUCCEEDED(rc)?SQLExecute(statement):rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLExecDirect(SQLHSTMT statement,SQLCHAR *text,SQLINTEGER length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLExecDirect(statement, text, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLExecDirectW(SQLHSTMT statement,SQLWCHAR *text,SQLINTEGER length){char *u=cs_utf16_to_utf8(text,length);SQLRETURN rc;if(!u)return SQL_ERROR;rc=SQLExecDirect(statement,(SQLCHAR *)u,SQL_NTS);free(u);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLExecDirectW(SQLHSTMT statement,SQLWCHAR *text,SQLINTEGER length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLExecDirectW(statement, text, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLExecDirectA(SQLHSTMT s,SQLCHAR *t,SQLINTEGER n){return SQLExecDirect(s,t,n);}

CSODBC_EXPORT SQLRETURN SQL_API SQLExecDirectA(SQLHSTMT s,SQLCHAR *t,SQLINTEGER n) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLExecDirectA(s, t, n);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLParamData(SQLHSTMT statement,SQLPOINTER *value){
    cs_stmt *s=(cs_stmt *)statement;SQLUSMALLINT i;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);
    if(!s->need_data_active)return cs_diag_add(&s->h,"HY010",0,"No data-at-execution operation is active");
    for(i=(SQLUSMALLINT)(s->at_exec_param+1);i<=s->num_params;i++)if(cs_param_needs_data(&s->params[i-1])){s->at_exec_param=i;if(value)*value=s->params[i-1].value;return SQL_NEED_DATA;}
    s->at_exec_param=0;s->need_data_active=0;return cs_execute_now(s);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLParamData(SQLHSTMT statement,SQLPOINTER *value) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLParamData(statement, value);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLPutData(SQLHSTMT statement,SQLPOINTER data,SQLLEN length){
    cs_stmt *s=(cs_stmt *)statement;cs_param_binding *p;SQLLEN needed;unsigned char *b;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);
    if(!s->need_data_active||!s->at_exec_param)return cs_diag_add(&s->h,"HY010",0,"No parameter is awaiting data");
    p=&s->params[s->at_exec_param-1];if(length==SQL_NULL_DATA){free(p->at_exec);p->at_exec=NULL;p->at_exec_len=SQL_NULL_DATA;return SQL_SUCCESS;}
    if(length==SQL_NTS)length=(SQLLEN)strlen((const char *)data);if(length<0)return cs_diag_add(&s->h,"HY090",0,"Invalid data length");
    needed=p->at_exec_len+length;if(needed>p->at_exec_cap){SQLLEN cap=p->at_exec_cap?p->at_exec_cap*2:256;while(cap<needed)cap*=2;b=(unsigned char *)realloc(p->at_exec,(size_t)cap);if(!b)return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");p->at_exec=b;p->at_exec_cap=cap;}
    if(length)memcpy(p->at_exec+p->at_exec_len,data,(size_t)length);p->at_exec_len=needed;return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLPutData(SQLHSTMT statement,SQLPOINTER data,SQLLEN length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLPutData(statement, data, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLRowCount(SQLHSTMT statement,SQLLEN *count){cs_stmt *s=(cs_stmt *)statement;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);if(count)*count=s->row_count;return SQL_SUCCESS;}

CSODBC_EXPORT SQLRETURN SQL_API SQLRowCount(SQLHSTMT statement,SQLLEN *count) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLRowCount(statement, count);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLMoreResults(SQLHSTMT statement){cs_stmt *s=(cs_stmt *)statement;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);cs_stmt_close(s);return SQL_NO_DATA;}

CSODBC_EXPORT SQLRETURN SQL_API SQLMoreResults(SQLHSTMT statement) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLMoreResults(statement);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLSMALLINT cs_column_sql_type(csqlc *cursor,SQLUSMALLINT col){
    switch(cubesql_cursor_columntype(cursor,col)){
        case CUBESQL_Type_Integer:return SQL_BIGINT;case CUBESQL_Type_Float:return SQL_DOUBLE;
        case CUBESQL_Type_Blob:return SQL_LONGVARBINARY;case CUBESQL_Type_Boolean:return SQL_BIT;
        case CUBESQL_Type_Date:return SQL_TYPE_DATE;case CUBESQL_Type_Time:return SQL_TYPE_TIME;
        case CUBESQL_Type_Timestamp:return SQL_TYPE_TIMESTAMP;case CUBESQL_Type_Currency:return SQL_DECIMAL;
        case CUBESQL_Type_Text:default:return SQL_VARCHAR;
    }
}

/*
 * Maps a declared column type - the text SQLite keeps in the catalogue, such as
 * "REAL" or "VARCHAR(40)" - onto an ODBC type, following the same affinity
 * rules the driver already applies in SQLColumns. Returns 0 when the text says
 * nothing useful, meaning "keep whatever the server reported".
 */
static SQLSMALLINT cs_decl_type_to_sql(const char *decl){
    char up[128];size_t i;
    if(!decl||!decl[0])return 0;
    for(i=0;decl[i]&&i+1<sizeof(up);i++)up[i]=(char)toupper((unsigned char)decl[i]);
    up[i]='\0';
    if(strstr(up,"INT"))return SQL_BIGINT;
    if(strstr(up,"CHAR")||strstr(up,"CLOB")||strstr(up,"TEXT"))return SQL_VARCHAR;
    if(strstr(up,"BLOB"))return SQL_LONGVARBINARY;
    if(strstr(up,"REAL")||strstr(up,"FLOA")||strstr(up,"DOUB"))return SQL_DOUBLE;
    if(strstr(up,"BOOL"))return SQL_BIT;
    if(strstr(up,"TIMESTAMP")||strstr(up,"DATETIME"))return SQL_TYPE_TIMESTAMP;
    if(!strcmp(up,"DATE"))return SQL_TYPE_DATE;
    if(!strcmp(up,"TIME"))return SQL_TYPE_TIME;
    if(strstr(up,"NUMERIC")||strstr(up,"DECIMAL"))return SQL_DECIMAL;
    return 0;
}

/*
 * Copies one cursor field into a NUL-terminated buffer. The SDK returns a
 * pointer into a packed buffer that is not NUL-terminated for data rows, so the
 * length it reports has to be honoured.
 */
static void cs_field_copy(csqlc *c,int row,int col,char *out,size_t cap){
    int len=0;char *v;size_t n;
    if(!cap)return;
    out[0]='\0';
    if(!c)return;
    v=cubesql_cursor_field(c,row,col,&len);
    if(!v||len<=0)return;
    n=(size_t)len;if(n>=cap)n=cap-1;
    memcpy(out,v,n);out[n]='\0';
}

/* Fills in decl_type for every column of one table, with a single catalogue query. */
static void cs_resolve_from_table(cs_stmt *s,const char *table,int ncols){
    char q[700],esc[300],cname[256],ctype[128],colname[256],coltable[256];
    csqlc *info;int rows,r,col;size_t i,n=0;
    if(!table||!table[0])return;
    for(i=0;table[i]&&n+2<sizeof(esc);i++){if(table[i]=='\'')esc[n++]='\'';esc[n++]=table[i];}
    esc[n]='\0';
    snprintf(q,sizeof(q),"PRAGMA table_info('%s');",esc);
    info=cubesql_select(s->dbc->db,q,kFALSE);
    if(!info){cubesql_clear_errors(s->dbc->db);return;}
    rows=cubesql_cursor_numrows(info);
    for(col=1;col<=ncols;col++){
        if(s->decl_type[col-1])continue;
        cs_field_copy(s->cursor,CUBESQL_COLTABLE,col,coltable,sizeof(coltable));
        if(!cs_ascii_equal(coltable,table))continue;
        cs_field_copy(s->cursor,CUBESQL_COLNAME,col,colname,sizeof(colname));
        for(r=1;r<=rows;r++){
            cs_field_copy(info,r,2,cname,sizeof(cname));
            if(cs_ascii_equal(cname,colname)){
                cs_field_copy(info,r,3,ctype,sizeof(ctype));
                s->decl_type[col-1]=cs_decl_type_to_sql(ctype);
                break;
            }
        }
    }
    cubesql_cursor_free(info);
}

/*
 * Resolves declared types once per result set, and only when it can help: if no
 * column came back as text there is nothing to improve and no query is issued.
 * Columns that are expressions rather than table columns have no table name and
 * are left as the server reported them.
 */
static void cs_resolve_column_types(cs_stmt *s){
    int ncols,col,need=0,done,d;
    char table[256];char seen[8][256];int nseen=0;
    if(s->types_resolved||!s->cursor)return;
    s->types_resolved=1;
    ncols=cubesql_cursor_numcolumns(s->cursor);
    if(ncols>CSODBC_MAX_COLS)ncols=CSODBC_MAX_COLS;
    for(col=1;col<=ncols;col++){
        s->decl_type[col-1]=0;
        if(cs_column_sql_type(s->cursor,(SQLUSMALLINT)col)==SQL_VARCHAR)need=1;
    }
    if(!need)return;
    for(col=1;col<=ncols;col++){
        if(cs_column_sql_type(s->cursor,(SQLUSMALLINT)col)!=SQL_VARCHAR)continue;
        cs_field_copy(s->cursor,CUBESQL_COLTABLE,col,table,sizeof(table));
        if(!table[0])continue;
        done=0;
        for(d=0;d<nseen;d++)if(cs_ascii_equal(seen[d],table)){done=1;break;}
        if(done)continue;
        if(nseen<8){cs_option_set(seen[nseen],sizeof(seen[nseen]),table);nseen++;}
        cs_resolve_from_table(s,table,ncols);
    }
}

/* Type reported to the application: the catalogue's answer when there is one. */
static SQLSMALLINT cs_stmt_column_type(cs_stmt *s,SQLUSMALLINT col){
    SQLSMALLINT base=cs_column_sql_type(s->cursor,col);
    if(base!=SQL_VARCHAR)return base;
    cs_resolve_column_types(s);
    if(col>=1&&col<=CSODBC_MAX_COLS&&s->decl_type[col-1])return s->decl_type[col-1];
    return base;
}

static const char *cs_sql_type_name(SQLSMALLINT type){
    switch(type){case SQL_BIGINT:return "BIGINT";case SQL_INTEGER:return "INTEGER";case SQL_SMALLINT:return "SMALLINT";
        case SQL_DOUBLE:return "DOUBLE";case SQL_REAL:return "REAL";case SQL_DECIMAL:return "DECIMAL";case SQL_BIT:return "BIT";
        case SQL_BINARY:return "BINARY";case SQL_VARBINARY:return "VARBINARY";case SQL_LONGVARBINARY:return "LONGVARBINARY";
        case SQL_TYPE_DATE:return "DATE";case SQL_TYPE_TIME:return "TIME";case SQL_TYPE_TIMESTAMP:return "TIMESTAMP";
        case SQL_LONGVARCHAR:return "LONGVARCHAR";case SQL_WVARCHAR:return "WVARCHAR";case SQL_VARCHAR:default:return "VARCHAR";}
}

static SQLULEN cs_sql_type_size(SQLSMALLINT type){
    switch(type){case SQL_BIT:return 1;case SQL_SMALLINT:return 5;case SQL_INTEGER:return 10;case SQL_BIGINT:return 19;
        case SQL_REAL:return 7;case SQL_DOUBLE:return 15;case SQL_DECIMAL:return 19;case SQL_TYPE_DATE:return 10;
        case SQL_TYPE_TIME:return 8;case SQL_TYPE_TIMESTAMP:return 29;case SQL_LONGVARBINARY:case SQL_LONGVARCHAR:return 0x7fffffffU;default:return 65535;}
}

static SQLRETURN SQL_API cs_i_SQLNumResultCols(SQLHSTMT statement,SQLSMALLINT *count){
    cs_stmt *s=(cs_stmt *)statement;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);
    if(count)*count=(SQLSMALLINT)(s->cursor?cubesql_cursor_numcolumns(s->cursor):0);return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLNumResultCols(SQLHSTMT statement,SQLSMALLINT *count) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLNumResultCols(statement, count);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLDescribeCol(SQLHSTMT statement,SQLUSMALLINT column,
    SQLCHAR *name,SQLSMALLINT capacity,SQLSMALLINT *name_len,SQLSMALLINT *type,
    SQLULEN *size,SQLSMALLINT *scale,SQLSMALLINT *nullable){
    cs_stmt *s=(cs_stmt *)statement;char *n;int raw_len;SQLLEN out_len=0;SQLSMALLINT t;SQLRETURN rc;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);
    if(!s->cursor)return cs_diag_add(&s->h,"07005",0,"Statement has no result columns");
    if(column<1||column>cubesql_cursor_numcolumns(s->cursor))return cs_diag_add(&s->h,"07009",0,"Invalid column number");
    n=cubesql_cursor_field(s->cursor,CUBESQL_COLNAME,column,&raw_len);t=cs_stmt_column_type(s,column);
    rc=cs_copy_ansi(name,capacity,&out_len,n?n:"",&s->h,s->dbc->ansi_charset);if(name_len)*name_len=(SQLSMALLINT)out_len;
    if(type)*type=t;if(size)*size=cs_sql_type_size(t);if(scale)*scale=t==SQL_DECIMAL?6:0;if(nullable)*nullable=SQL_NULLABLE;return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLDescribeCol(SQLHSTMT statement,SQLUSMALLINT column,
    SQLCHAR *name,SQLSMALLINT capacity,SQLSMALLINT *name_len,SQLSMALLINT *type,
    SQLULEN *size,SQLSMALLINT *scale,SQLSMALLINT *nullable) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLDescribeCol(statement, column, name, capacity, name_len, type, size, scale, nullable);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLDescribeColW(SQLHSTMT statement,SQLUSMALLINT column,
    SQLWCHAR *name,SQLSMALLINT capacity,SQLSMALLINT *name_len,SQLSMALLINT *type,
    SQLULEN *size,SQLSMALLINT *scale,SQLSMALLINT *nullable){
    cs_stmt *s=(cs_stmt *)statement;char *n;int raw_len;SQLLEN out_len=0;SQLSMALLINT t;SQLRETURN rc;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);
    if(!s->cursor)return cs_diag_add(&s->h,"07005",0,"Statement has no result columns");if(column<1||column>cubesql_cursor_numcolumns(s->cursor))return cs_diag_add(&s->h,"07009",0,"Invalid column number");
    n=cubesql_cursor_field(s->cursor,CUBESQL_COLNAME,column,&raw_len);t=cs_stmt_column_type(s,column);rc=cs_copy_utf16(name,capacity,&out_len,n?n:"",&s->h);
    if(name_len)*name_len=(SQLSMALLINT)out_len;if(type)*type=t;if(size)*size=cs_sql_type_size(t);if(scale)*scale=t==SQL_DECIMAL?6:0;if(nullable)*nullable=SQL_NULLABLE;return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLDescribeColW(SQLHSTMT statement,SQLUSMALLINT column,
    SQLWCHAR *name,SQLSMALLINT capacity,SQLSMALLINT *name_len,SQLSMALLINT *type,
    SQLULEN *size,SQLSMALLINT *scale,SQLSMALLINT *nullable) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLDescribeColW(statement, column, name, capacity, name_len, type, size, scale, nullable);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLBindCol(SQLHSTMT statement,SQLUSMALLINT column,
    SQLSMALLINT c_type,SQLPOINTER value,SQLLEN capacity,SQLLEN *indicator){
    cs_stmt *s=(cs_stmt *)statement;cs_col_binding *b;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);
    if(column<1||column>CSODBC_MAX_COLS)return cs_diag_add(&s->h,"07009",0,"Invalid column number");b=&s->columns[column-1];
    if(!value){memset(b,0,sizeof(*b));return SQL_SUCCESS;}b->c_type=c_type;b->value=value;b->buffer_length=capacity;b->indicator=indicator;return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLBindCol(SQLHSTMT statement,SQLUSMALLINT column,
    SQLSMALLINT c_type,SQLPOINTER value,SQLLEN capacity,SQLLEN *indicator) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLBindCol(statement, column, c_type, value, capacity, indicator);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN cs_numeric_error(cs_stmt *s,const char *message){return cs_diag_add(&s->h,"22003",0,"%s",message);}

static SQLRETURN cs_convert_value(cs_stmt *s,const unsigned char *data,SQLLEN len,
    SQLSMALLINT source_type,SQLSMALLINT target_type,SQLPOINTER out,SQLLEN capacity,
    SQLLEN *indicator,SQLLEN offset,int partial){
    char tmp[128];char *end=NULL;long long sv;unsigned long long uv;double dv;SQLLEN remain,copy;
    if(!data||len==SQL_NULL_DATA){if(indicator)*indicator=SQL_NULL_DATA;return SQL_SUCCESS;}
    if(target_type==SQL_C_DEFAULT)target_type=cs_default_c_type(source_type);
    if(s->max_length&&len>(SQLLEN)s->max_length)len=(SQLLEN)s->max_length;
    if(target_type==SQL_C_CHAR){
        if(indicator)*indicator=len;if(!out||capacity<=0)return SQL_SUCCESS;if(offset>len)offset=len;remain=len-offset;
        copy=remain<capacity-1?remain:capacity-1;if(copy>0)memcpy(out,data+offset,(size_t)copy);((char *)out)[copy]=0;
        if(copy<remain){cs_diag_add(&s->h,"01004",0,"String data, right truncated");s->h.last_return=SQL_SUCCESS_WITH_INFO;return SQL_SUCCESS_WITH_INFO;}return SQL_SUCCESS;
    }
    if(target_type==SQL_C_BINARY){
        if(indicator)*indicator=len;if(!out||capacity<=0)return SQL_SUCCESS;if(offset>len)offset=len;remain=len-offset;copy=remain<capacity?remain:capacity;if(copy>0)memcpy(out,data+offset,(size_t)copy);
        if(copy<remain){cs_diag_add(&s->h,"01004",0,"Binary data, right truncated");s->h.last_return=SQL_SUCCESS_WITH_INFO;return SQL_SUCCESS_WITH_INFO;}return SQL_SUCCESS;
    }
    if(target_type==SQL_C_WCHAR){
        char *u8=cs_strndup0((const char *)data,(size_t)len);size_t total,wcap=(size_t)(capacity/sizeof(SQLWCHAR));SQLRETURN rc=SQL_SUCCESS;if(!u8)return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");
        total=cs_utf8_to_utf16_buf(u8,NULL,0);if(indicator)*indicator=(SQLLEN)(total*sizeof(SQLWCHAR));if(out&&wcap)cs_utf8_to_utf16_buf(u8,(SQLWCHAR *)out,wcap);
        if(out&&wcap<=total){cs_diag_add(&s->h,"01004",0,"String data, right truncated");s->h.last_return=SQL_SUCCESS_WITH_INFO;rc=SQL_SUCCESS_WITH_INFO;}free(u8);return rc;
    }
    if((size_t)len>=sizeof(tmp))return cs_numeric_error(s,"Numeric value is too long");memcpy(tmp,data,(size_t)len);tmp[len]='\0';errno=0;
    switch(target_type){
        case SQL_C_SHORT:case SQL_C_SSHORT:sv=strtoll(tmp,&end,10);if(errno||end==tmp||sv<INT16_MIN||sv>INT16_MAX)return cs_numeric_error(s,"Small integer out of range");if(out)*(int16_t *)out=(int16_t)sv;if(indicator)*indicator=sizeof(int16_t);break;
        /*
         * I tipi C a 8 bit mancavano del tutto: cs_ctype_stride li conosceva
         * gia', ma la conversione rispondeva HY003. Un consumer che chieda
         * SQL_C_STINYINT per una colonna piccola non riusciva a leggerla.
         */
        case SQL_C_TINYINT:case SQL_C_STINYINT:sv=strtoll(tmp,&end,10);if(errno||end==tmp||sv<INT8_MIN||sv>INT8_MAX)return cs_numeric_error(s,"Tiny integer out of range");if(out)*(signed char *)out=(signed char)sv;if(indicator)*indicator=sizeof(signed char);break;
        case SQL_C_UTINYINT:uv=strtoull(tmp,&end,10);if(errno||end==tmp||uv>UINT8_MAX)return cs_numeric_error(s,"Unsigned tiny integer out of range");if(out)*(unsigned char *)out=(unsigned char)uv;if(indicator)*indicator=sizeof(unsigned char);break;
        case SQL_C_USHORT:uv=strtoull(tmp,&end,10);if(errno||end==tmp||uv>UINT16_MAX)return cs_numeric_error(s,"Unsigned small integer out of range");if(out)*(uint16_t *)out=(uint16_t)uv;if(indicator)*indicator=sizeof(uint16_t);break;
        case SQL_C_LONG:case SQL_C_SLONG:sv=strtoll(tmp,&end,10);if(errno||end==tmp||sv<INT32_MIN||sv>INT32_MAX)return cs_numeric_error(s,"Integer out of range");if(out)*(int32_t *)out=(int32_t)sv;if(indicator)*indicator=sizeof(int32_t);break;
        case SQL_C_ULONG:uv=strtoull(tmp,&end,10);if(errno||end==tmp||uv>UINT32_MAX)return cs_numeric_error(s,"Unsigned integer out of range");if(out)*(uint32_t *)out=(uint32_t)uv;if(indicator)*indicator=sizeof(uint32_t);break;
        case SQL_C_SBIGINT:sv=strtoll(tmp,&end,10);if(errno||end==tmp)return cs_numeric_error(s,"Big integer out of range");if(out)*(int64_t *)out=(int64_t)sv;if(indicator)*indicator=sizeof(int64_t);break;
        case SQL_C_UBIGINT:uv=strtoull(tmp,&end,10);if(errno||end==tmp)return cs_numeric_error(s,"Unsigned big integer out of range");if(out)*(uint64_t *)out=(uint64_t)uv;if(indicator)*indicator=sizeof(uint64_t);break;
        case SQL_C_FLOAT:dv=strtod(tmp,&end);if(errno||end==tmp)return cs_numeric_error(s,"Floating point value out of range");if(out)*(float *)out=(float)dv;if(indicator)*indicator=sizeof(float);break;
        case SQL_C_DOUBLE:dv=strtod(tmp,&end);if(errno||end==tmp)return cs_numeric_error(s,"Floating point value out of range");if(out)*(double *)out=dv;if(indicator)*indicator=sizeof(double);break;
        case SQL_C_BIT:sv=strtoll(tmp,&end,10);if(end==tmp||sv<0||sv>1)return cs_numeric_error(s,"Bit value must be zero or one");if(out)*(unsigned char *)out=(unsigned char)sv;if(indicator)*indicator=1;break;
        case SQL_C_DATE:case SQL_C_TYPE_DATE:{SQL_DATE_STRUCT *d=(SQL_DATE_STRUCT *)out;int y,m,day;if(sscanf(tmp,"%d-%d-%d",&y,&m,&day)!=3)return cs_diag_add(&s->h,"22007",0,"Invalid date value");if(d){d->year=(SQLSMALLINT)y;d->month=(SQLUSMALLINT)m;d->day=(SQLUSMALLINT)day;}if(indicator)*indicator=sizeof(*d);break;}
        case SQL_C_TIME:case SQL_C_TYPE_TIME:{SQL_TIME_STRUCT *t=(SQL_TIME_STRUCT *)out;int h,m,sec;if(sscanf(tmp,"%d:%d:%d",&h,&m,&sec)!=3)return cs_diag_add(&s->h,"22007",0,"Invalid time value");if(t){t->hour=(SQLUSMALLINT)h;t->minute=(SQLUSMALLINT)m;t->second=(SQLUSMALLINT)sec;}if(indicator)*indicator=sizeof(*t);break;}
        case SQL_C_TIMESTAMP:case SQL_C_TYPE_TIMESTAMP:{SQL_TIMESTAMP_STRUCT *t=(SQL_TIMESTAMP_STRUCT *)out;int y,mo,d,h,mi,se;unsigned frac=0;int fields=sscanf(tmp,"%d-%d-%d %d:%d:%d.%u",&y,&mo,&d,&h,&mi,&se,&frac);if(fields<6)return cs_diag_add(&s->h,"22007",0,"Invalid timestamp value");if(t){t->year=(SQLSMALLINT)y;t->month=(SQLUSMALLINT)mo;t->day=(SQLUSMALLINT)d;t->hour=(SQLUSMALLINT)h;t->minute=(SQLUSMALLINT)mi;t->second=(SQLUSMALLINT)se;t->fraction=frac;}if(indicator)*indicator=sizeof(*t);break;}
                /*
         * SQL_C_DATE/TIME/TIMESTAMP (9/10/11) sono le grafie ODBC 2.x di
         * SQL_C_TYPE_DATE/TIME/TIMESTAMP (91/92/93) e usano le stesse strutture.
         * Finche' il driver si dichiara ODBC 2.0 il Driver Manager converte le
         * seconde nelle prime, quindi vanno accettate entrambe: senza di esse
         * ogni colonna di tipo data/ora falliva con HY003.
         */        default:return cs_diag_add(&s->h,"HY003",0,"Unsupported C target type %d",target_type);
    }(void)partial;return SQL_SUCCESS;
}

/*
 * Rowset binding. ODBC lays a rowset out either column-wise, where every bound
 * buffer is an array of row_array_size elements, or row-wise, where
 * SQL_ATTR_ROW_BIND_TYPE is the stride of the application's row struct. Both
 * forms then add SQL_ATTR_ROW_BIND_OFFSET_PTR to every address.
 */
/*
 * Stride of one element in a column-wise array. ODBC lets an application bind a
 * fixed-length C type with BufferLength 0, so the stride has to come from the C
 * type in that case; taking it from BufferLength would make every row of the
 * rowset land on top of the first.
 */
static SQLLEN cs_ctype_stride(SQLSMALLINT c_type,SQLLEN buffer_length){
    switch(c_type){
        case SQL_C_BIT:case SQL_C_STINYINT:case SQL_C_UTINYINT:case SQL_C_TINYINT:return 1;
        case SQL_C_SHORT:case SQL_C_SSHORT:case SQL_C_USHORT:return 2;
        case SQL_C_LONG:case SQL_C_SLONG:case SQL_C_ULONG:return 4;
        case SQL_C_FLOAT:return (SQLLEN)sizeof(float);
        case SQL_C_DOUBLE:return (SQLLEN)sizeof(double);
        case SQL_C_SBIGINT:case SQL_C_UBIGINT:return 8;
        case SQL_C_DATE:case SQL_C_TYPE_DATE:return (SQLLEN)sizeof(SQL_DATE_STRUCT);
        case SQL_C_TIME:case SQL_C_TYPE_TIME:return (SQLLEN)sizeof(SQL_TIME_STRUCT);
        case SQL_C_TIMESTAMP:case SQL_C_TYPE_TIMESTAMP:return (SQLLEN)sizeof(SQL_TIMESTAMP_STRUCT);
        default:return buffer_length;   /* CHAR, WCHAR, BINARY: application sized */
    }
}

static SQLPOINTER cs_bind_addr(cs_stmt *s,SQLPOINTER base,SQLLEN element,SQLULEN row){
    char *p=(char *)base;
    if(!p)return NULL;
    if(s->row_bind_offset)p+=*s->row_bind_offset;
    if(s->row_bind_type==SQL_BIND_BY_COLUMN)p+=(SQLLEN)row*element;
    else p+=(SQLLEN)row*(SQLLEN)s->row_bind_type;
    return (SQLPOINTER)p;
}

static SQLLEN *cs_bind_ind(cs_stmt *s,SQLLEN *base,SQLULEN row){
    char *p=(char *)base;
    if(!p)return NULL;
    if(s->row_bind_offset)p+=*s->row_bind_offset;
    if(s->row_bind_type==SQL_BIND_BY_COLUMN)p+=(SQLLEN)row*(SQLLEN)sizeof(SQLLEN);
    else p+=(SQLLEN)row*(SQLLEN)s->row_bind_type;
    return (SQLLEN *)p;
}

/*
 * Reads one field in the encoding the target C type expects. When the caller
 * wants SQL_C_CHAR on an ANSI connection the UTF-8 bytes CubeSQL returned are
 * converted first, so every length and chunking offset downstream is already
 * measured in the bytes the application will actually receive.
 *
 * "*owned" is set when the result must be freed by the caller.
 */
static char *cs_field_bytes(cs_stmt *s,int row,int col,SQLSMALLINT c_type,
                            int *len,char **owned){
    char *data=cubesql_cursor_field(s->cursor,row,col,len);
    *owned=NULL;
    if(!data||!s->dbc->ansi_charset)return data;
    if(c_type!=SQL_C_CHAR)return data;
    /* Only text needs converting; numeric targets parse ASCII either way. */
    if(cs_column_sql_type(s->cursor,(SQLUSMALLINT)col)==SQL_LONGVARBINARY)return data;
    {
        size_t converted=0;
        char *ansi=cs_utf8_to_ansi(data,(size_t)(*len<0?0:*len),&converted);
        if(!ansi)return data;
        *owned=ansi;*len=(int)converted;
        return ansi;
    }
}

/* Copies "count" rows starting at absolute row "first" into the bound buffers. */
static SQLRETURN cs_fetch_rowset(cs_stmt *s,SQLLEN first,SQLULEN count){
    SQLULEN r;SQLRETURN overall=SQL_SUCCESS;
    int cols=cubesql_cursor_numcolumns(s->cursor);
    for(r=0;r<count;r++){
        SQLLEN row=first+(SQLLEN)r;SQLRETURN row_rc=SQL_SUCCESS;int i;
        for(i=1;i<=cols&&i<=CSODBC_MAX_COLS;i++){
            cs_col_binding *b=&s->columns[i-1];int len;char *data,*owned;SQLRETURN rc;
            if(!b->value&&!b->indicator)continue;
            data=cs_field_bytes(s,(int)row,i,b->c_type,&len,&owned);
            rc=cs_convert_value(s,(unsigned char *)data,data?len:SQL_NULL_DATA,
                                cs_column_sql_type(s->cursor,(SQLUSMALLINT)i),b->c_type,
                                cs_bind_addr(s,b->value,cs_ctype_stride(b->c_type,b->buffer_length),r),b->buffer_length,
                                cs_bind_ind(s,b->indicator,r),0,0);
            free(owned);
            if(rc==SQL_ERROR)row_rc=SQL_ERROR;
            else if(rc==SQL_SUCCESS_WITH_INFO&&row_rc==SQL_SUCCESS)row_rc=SQL_SUCCESS_WITH_INFO;
        }
        if(s->row_status)
            s->row_status[r]=(SQLUSMALLINT)(row_rc==SQL_ERROR?SQL_ROW_ERROR:
                             row_rc==SQL_SUCCESS_WITH_INFO?SQL_ROW_SUCCESS_WITH_INFO:SQL_ROW_SUCCESS);
        if(row_rc==SQL_ERROR)overall=SQL_SUCCESS_WITH_INFO;
        else if(row_rc==SQL_SUCCESS_WITH_INFO&&overall==SQL_SUCCESS)overall=SQL_SUCCESS_WITH_INFO;
    }
    return overall;
}

static SQLRETURN SQL_API cs_i_SQLFetchScroll(SQLHSTMT statement,SQLSMALLINT orientation,SQLLEN offset){
    cs_stmt *s=(cs_stmt *)statement;SQLLEN first,total;SQLULEN want,count,r;SQLRETURN rc;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;
    cs_diag_clear(&s->h);
    if(s->rows_fetched)*s->rows_fetched=0;
    want=s->row_array_size?s->row_array_size:1;
    if(s->row_status)for(r=0;r<want;r++)s->row_status[r]=SQL_ROW_NOROW;
    if(!s->cursor)return cs_diag_add(&s->h,"24000",0,"No cursor is open");
    total=cubesql_cursor_numrows(s->cursor);
    if(total<0)total=0;
    if(s->max_rows&&total>(SQLLEN)s->max_rows)total=(SQLLEN)s->max_rows;
    switch(orientation){
        case SQL_FETCH_NEXT:first=(SQLLEN)s->rowset_start+(SQLLEN)s->rowset_count;if(first<1)first=1;break;
        case SQL_FETCH_FIRST:first=1;break;
        case SQL_FETCH_LAST:first=total-(SQLLEN)want+1;if(first<1)first=1;break;
        case SQL_FETCH_PRIOR:
            first=(SQLLEN)s->rowset_start-(SQLLEN)want;
            /* Partial first rowset rather than SQL_NO_DATA, as the spec asks. */
            if(first<1)first=(s->rowset_start>1)?1:0;
            break;
        case SQL_FETCH_ABSOLUTE:first=offset>=0?offset:total+offset+1;break;
        case SQL_FETCH_RELATIVE:first=(SQLLEN)s->rowset_start+offset;break;
        default:return cs_diag_add(&s->h,"HY106",0,"Invalid fetch orientation");
    }
    if(first<1||first>total){
        s->rowset_start=(SQLULEN)(first<1?0:first);s->rowset_count=0;s->current_row=first;
        return SQL_NO_DATA;
    }
    count=(SQLULEN)(total-first+1);
    if(count>want)count=want;
    cubesql_cursor_seek(s->cursor,(int)first);
    memset(s->getdata_offset,0,sizeof(s->getdata_offset));
    s->rowset_start=(SQLULEN)first;s->rowset_count=count;s->current_row=first;
    rc=cs_fetch_rowset(s,first,count);
    if(s->rows_fetched)*s->rows_fetched=count;
    return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLFetchScroll(SQLHSTMT statement,SQLSMALLINT orientation,SQLLEN offset) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLFetchScroll(statement, orientation, offset);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLFetch(SQLHSTMT statement){return SQLFetchScroll(statement,SQL_FETCH_NEXT,0);}

CSODBC_EXPORT SQLRETURN SQL_API SQLFetch(SQLHSTMT statement) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLFetch(statement);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
/*
 * The ODBC 2 entry point reports through its own pointers. They are restored
 * afterwards so a later SQLFetch does not keep writing into the caller's stack.
 */
static SQLRETURN SQL_API cs_i_SQLExtendedFetch(SQLHSTMT statement,SQLUSMALLINT orientation,SQLLEN offset,SQLULEN *rows,SQLUSMALLINT *status){
    cs_stmt *s=(cs_stmt *)statement;SQLULEN *saved_rows;SQLUSMALLINT *saved_status;SQLRETURN rc;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;
    saved_rows=s->rows_fetched;saved_status=s->row_status;
    s->rows_fetched=rows;s->row_status=status;
    rc=SQLFetchScroll(statement,(SQLSMALLINT)orientation,offset);
    s->rows_fetched=saved_rows;s->row_status=saved_status;
    return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLExtendedFetch(SQLHSTMT statement,SQLUSMALLINT orientation,SQLLEN offset,SQLULEN *rows,SQLUSMALLINT *status) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLExtendedFetch(statement, orientation, offset, rows, status);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetData(SQLHSTMT statement,SQLUSMALLINT column,
    SQLSMALLINT target_type,SQLPOINTER value,SQLLEN capacity,SQLLEN *indicator){
    cs_stmt *s=(cs_stmt *)statement;char *data,*owned=NULL;int len;SQLRETURN rc;SQLLEN old,consumed;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);if(!s->cursor||s->current_row<1)return cs_diag_add(&s->h,"24000",0,"Cursor is not positioned on a row");
    if(column<1||column>cubesql_cursor_numcolumns(s->cursor))return cs_diag_add(&s->h,"07009",0,"Invalid column number");
    data=cs_field_bytes(s,(int)s->current_row,column,target_type,&len,&owned);old=s->getdata_offset[column-1];
    if(data&&target_type==SQL_C_WCHAR){
        char *u8=cs_strndup0(data,(size_t)len);size_t total,cap_units,copy;SQLWCHAR *wide;
        if(!u8)return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");total=cs_utf8_to_utf16_buf(u8,NULL,0);free(u8);
        if(old>=(SQLLEN)total)return SQL_NO_DATA;if(indicator)*indicator=(SQLLEN)(total*sizeof(SQLWCHAR));cap_units=capacity>0?(size_t)capacity/sizeof(SQLWCHAR):0;
        wide=(SQLWCHAR *)malloc((total+1)*sizeof(SQLWCHAR));if(!wide)return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");u8=cs_strndup0(data,(size_t)len);if(!u8){free(wide);return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");}cs_utf8_to_utf16_buf(u8,wide,total+1);free(u8);
        copy=(size_t)((SQLLEN)total-old);if(!cap_units)copy=0;else if(copy>=cap_units)copy=cap_units-1;if(value&&cap_units){memcpy(value,wide+old,copy*sizeof(SQLWCHAR));((SQLWCHAR *)value)[copy]=0;}free(wide);s->getdata_offset[column-1]=old+(SQLLEN)copy;
        if(s->getdata_offset[column-1]<(SQLLEN)total){cs_diag_add(&s->h,"01004",0,"String data, right truncated");s->h.last_return=SQL_SUCCESS_WITH_INFO;return SQL_SUCCESS_WITH_INFO;}return SQL_SUCCESS;
    }
    if(data&&old>=len&&(target_type==SQL_C_CHAR||target_type==SQL_C_BINARY)){free(owned);return SQL_NO_DATA;}
    rc=cs_convert_value(s,(unsigned char *)data,data?len:SQL_NULL_DATA,cs_column_sql_type(s->cursor,column),target_type,value,capacity,indicator,old,1);
    if(data){if(target_type==SQL_C_CHAR)consumed=capacity>0?capacity-1:0;else if(target_type==SQL_C_BINARY)consumed=capacity>0?capacity:0;else if(target_type==SQL_C_WCHAR)consumed=len;else consumed=len;if(consumed<0)consumed=0;s->getdata_offset[column-1]=old+consumed;if(s->getdata_offset[column-1]>len)s->getdata_offset[column-1]=len;}
    free(owned);
    return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetData(SQLHSTMT statement,SQLUSMALLINT column,
    SQLSMALLINT target_type,SQLPOINTER value,SQLLEN capacity,SQLLEN *indicator) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetData(statement, column, target_type, value, capacity, indicator);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLLEN *cs_numeric_attr_ptr(SQLPOINTER p){return (SQLLEN *)p;}

/*
 * Column attributes whose value is a string rather than a number.
 *
 * SQLColAttribute and SQLColAttributeW both have to agree on this: the ANSI
 * entry point uses it to decide what to copy out as text, the Unicode one to
 * decide what to convert to UTF-16. They used to carry two hand-maintained
 * copies of the list, and the copies drifted - SQL_COLUMN_NAME reached one and
 * not the other, so SQLColAttributeW left the caller's buffer untouched and
 * every consumer that reads column names through the Unicode entry point (which
 * is the one the Driver Manager calls) got an empty string back.
 *
 * Most ODBC 2.x identifiers share a value with their 3.x counterpart -
 * SQL_COLUMN_TYPE_NAME is SQL_DESC_TYPE_NAME, SQL_COLUMN_LABEL is
 * SQL_DESC_LABEL, and so on - so only SQL_COLUMN_NAME needs naming separately.
 */
static int cs_colattr_is_string(SQLUSMALLINT field){
    return field==SQL_DESC_NAME||field==SQL_COLUMN_NAME||field==SQL_DESC_LABEL||
           field==SQL_DESC_BASE_COLUMN_NAME||field==SQL_DESC_TABLE_NAME||
           field==SQL_DESC_BASE_TABLE_NAME||field==SQL_DESC_CATALOG_NAME||
           field==SQL_DESC_SCHEMA_NAME||field==SQL_DESC_TYPE_NAME||
           field==SQL_DESC_LOCAL_TYPE_NAME;
}

static SQLRETURN SQL_API cs_i_SQLColAttribute(SQLHSTMT statement,SQLUSMALLINT column,
    SQLUSMALLINT field,SQLPOINTER chars,SQLSMALLINT capacity,SQLSMALLINT *char_len,
#ifdef _WIN64
    SQLLEN *numeric
#else
    SQLPOINTER numeric
#endif
){
    cs_stmt *s=(cs_stmt *)statement;SQLLEN *num=cs_numeric_attr_ptr((SQLPOINTER)numeric);SQLLEN n=0;char *name=NULL,*table=NULL;int rawlen;SQLSMALLINT type;const char *str="";SQLRETURN rc=SQL_SUCCESS;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);if(!s->cursor)return cs_diag_add(&s->h,"07005",0,"Statement has no result columns");
    if(column<1||column>cubesql_cursor_numcolumns(s->cursor))return cs_diag_add(&s->h,"07009",0,"Invalid column number");
    type=cs_stmt_column_type(s,column);name=cubesql_cursor_field(s->cursor,CUBESQL_COLNAME,column,&rawlen);table=cubesql_cursor_field(s->cursor,CUBESQL_COLTABLE,column,&rawlen);
    switch(field){
        case SQL_DESC_NAME:case SQL_DESC_LABEL:case SQL_DESC_BASE_COLUMN_NAME:str=name?name:"";break;
        case SQL_DESC_TABLE_NAME:case SQL_DESC_BASE_TABLE_NAME:str=table?table:"";break;
        case SQL_DESC_CATALOG_NAME:str=s->dbc->database;break;case SQL_DESC_SCHEMA_NAME:str="";break;
        case SQL_DESC_TYPE_NAME:case SQL_DESC_LOCAL_TYPE_NAME:str=cs_sql_type_name(type);break;
        case SQL_DESC_CONCISE_TYPE:case SQL_DESC_TYPE:if(num)*num=type;break;
        case SQL_DESC_LENGTH:case SQL_DESC_OCTET_LENGTH:case SQL_DESC_DISPLAY_SIZE:if(num)*num=(SQLLEN)cs_sql_type_size(type);break;
        case SQL_DESC_PRECISION:if(num)*num=(SQLLEN)cs_sql_type_size(type);break;case SQL_DESC_SCALE:if(num)*num=type==SQL_DECIMAL?6:0;break;
        case SQL_DESC_NULLABLE:if(num)*num=SQL_NULLABLE;break;case SQL_DESC_UNSIGNED:if(num)*num=SQL_FALSE;break;
        case SQL_DESC_CASE_SENSITIVE:if(num)*num=(type==SQL_VARCHAR||type==SQL_LONGVARCHAR)?SQL_TRUE:SQL_FALSE;break;
        case SQL_DESC_SEARCHABLE:if(num)*num=SQL_PRED_BASIC;break;case SQL_DESC_UPDATABLE:if(num)*num=SQL_ATTR_READONLY;break;
        case SQL_DESC_AUTO_UNIQUE_VALUE:case SQL_DESC_FIXED_PREC_SCALE:if(num)*num=SQL_FALSE;break;
        case SQL_DESC_NUM_PREC_RADIX:if(num)*num=(type==SQL_BIGINT||type==SQL_INTEGER||type==SQL_DOUBLE||type==SQL_DECIMAL)?10:0;break;
        /*
         * ODBC 2.x field identifiers. Most of them share a numeric value with
         * their 3.x counterpart above (SQL_COLUMN_TYPE_NAME is SQL_DESC_TYPE_NAME
         * and so on), but these six do not and used to fall through to HY091.
         * SQL_COLUMN_NAME in particular is what an ODBC 2 application - and the
         * Driver Manager, whenever it decides to talk 2.x to us - sends to read
         * a column name, so rejecting it made column metadata unreadable.
         */
        case SQL_COLUMN_NAME:str=name?name:"";break;
        case SQL_COLUMN_COUNT:if(num)*num=(SQLLEN)cubesql_cursor_numcolumns(s->cursor);break;
        case SQL_COLUMN_LENGTH:if(num)*num=(SQLLEN)cs_sql_type_size(type);break;
        case SQL_COLUMN_PRECISION:if(num)*num=(SQLLEN)cs_sql_type_size(type);break;
        case SQL_COLUMN_SCALE:if(num)*num=type==SQL_DECIMAL?6:0;break;
        case SQL_COLUMN_NULLABLE:if(num)*num=SQL_NULLABLE;break;
        default:return cs_diag_add(&s->h,"HY091",0,"Invalid column attribute %u",field);
    }
    if(cs_colattr_is_string(field)){rc=cs_copy_ansi((SQLCHAR *)chars,capacity,&n,str,&s->h,s->dbc->ansi_charset);if(char_len)*char_len=(SQLSMALLINT)n;}
    return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLColAttribute(SQLHSTMT statement,SQLUSMALLINT column,
    SQLUSMALLINT field,SQLPOINTER chars,SQLSMALLINT capacity,SQLSMALLINT *char_len,
#ifdef _WIN64
    SQLLEN *numeric
#else
    SQLPOINTER numeric
#endif
) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLColAttribute(statement, column, field, chars, capacity, char_len, numeric);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLColAttributes(SQLHSTMT s,SQLUSMALLINT c,SQLUSMALLINT f,SQLPOINTER ch,SQLSMALLINT cap,SQLSMALLINT *len,SQLLEN *num){return SQLColAttribute(s,c,f,ch,cap,len,num);}

CSODBC_EXPORT SQLRETURN SQL_API SQLColAttributes(SQLHSTMT s,SQLUSMALLINT c,SQLUSMALLINT f,SQLPOINTER ch,SQLSMALLINT cap,SQLSMALLINT *len,SQLLEN *num) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLColAttributes(s, c, f, ch, cap, len, num);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static char *cs_sql_literal(const SQLCHAR *value,SQLSMALLINT length,const char *fallback){
    size_t i,n=value?cs_input_len(value,length):strlen(fallback?fallback:"");const char *src=value?(const char *)value:(fallback?fallback:"");char *out=(char *)malloc(n*2+3);size_t p=0;if(!out)return NULL;out[p++]='\'';
    for(i=0;i<n;i++){if(src[i]=='\'')out[p++]='\'';out[p++]=src[i];}out[p++]='\'';out[p]='\0';return out;
}

static SQLRETURN cs_meta_exec(cs_stmt *s,char *query){SQLRETURN rc=SQLExecDirect((SQLHSTMT)s,(SQLCHAR *)query,SQL_NTS);free(query);return rc;}

static char *cs_query_alloc(size_t cap){char *q=(char *)calloc(1,cap);return q;}

static SQLRETURN cs_empty_metadata(SQLHSTMT statement,const char *columns);

/* Renders a value as a single-quoted SQL literal, or NULL when it is empty. */
static void cs_literal_or_null(char *out,size_t cap,const char *value){
    size_t i,n=0;
    if(!value||!*value){snprintf(out,cap,"NULL");return;}
    if(cap<4){snprintf(out,cap,"NULL");return;}
    out[n++]='\'';
    for(i=0;value[i]&&n+3<cap;i++){if(value[i]=='\'')out[n++]='\'';out[n++]=value[i];}
    out[n++]='\'';out[n]='\0';
}

/* Copies an ODBC string argument into a NUL-terminated buffer. */
static void cs_arg_text(char *out,size_t cap,SQLCHAR *value,SQLSMALLINT length){
    size_t n=value?cs_input_len(value,length):0;
    if(n>=cap)n=cap-1;
    if(n)memcpy(out,value,n);
    out[n]='\0';
}

/*
 * CubeSQL exposes one database per connection, so the ODBC catalog is the
 * current database. A request naming a different catalog cannot be answered
 * without switching databases underneath the application, so it yields an empty
 * result rather than silently reporting the wrong database's objects.
 */
static int cs_catalog_matches(cs_stmt *s,SQLCHAR *catalog,SQLSMALLINT length){
    char buf[512];
    cs_arg_text(buf,sizeof(buf),catalog,length);
    if(!buf[0]||!strcmp(buf,"%"))return 1;
    return cs_ascii_equal(buf,s->dbc->database);
}

/* SQLTables with catalog "%" and empty schema and table lists the catalogs. */
static SQLRETURN cs_tables_catalog_list(cs_stmt *s){
    csqlc *c;char *q;size_t cap=4096,used=0;int rows,row;
    c=cubesql_select(s->dbc->db,"SHOW DATABASES;",kFALSE);
    if(!c){cubesql_clear_errors(s->dbc->db);
        return cs_empty_metadata((SQLHSTMT)s,"NULL TABLE_CAT,NULL TABLE_SCHEM,NULL TABLE_NAME,NULL TABLE_TYPE,NULL REMARKS");}
    rows=cubesql_cursor_numrows(c);
    q=cs_query_alloc(cap);
    if(!q){cubesql_cursor_free(c);return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");}
    for(row=1;row<=rows;row++){
        char *name=cubesql_cursor_cstring(c,row,1);char escaped[600];size_t i,n=0;
        if(!name)continue;
        for(i=0;name[i]&&n+2<sizeof(escaped);i++){if(name[i]=='\'')escaped[n++]='\'';escaped[n++]=name[i];}
        escaped[n]='\0';free(name);
        if(used+n+160>cap)break;
        used+=(size_t)snprintf(q+used,cap-used,
            "%sSELECT '%s' TABLE_CAT,NULL TABLE_SCHEM,NULL TABLE_NAME,NULL TABLE_TYPE,NULL REMARKS",
            used?" UNION ALL ":"",escaped);
    }
    cubesql_cursor_free(c);
    if(!used){free(q);
        return cs_empty_metadata((SQLHSTMT)s,"NULL TABLE_CAT,NULL TABLE_SCHEM,NULL TABLE_NAME,NULL TABLE_TYPE,NULL REMARKS");}
    return cs_meta_exec(s,q);
}

static SQLRETURN SQL_API cs_i_SQLTables(SQLHSTMT statement,SQLCHAR *catalog,SQLSMALLINT catalog_len,
    SQLCHAR *schema,SQLSMALLINT schema_len,SQLCHAR *table,SQLSMALLINT table_len,
    SQLCHAR *types,SQLSMALLINT types_len){
    cs_stmt *s=(cs_stmt *)statement;char *pat,*q;const char *type_filter="type IN ('table','view')";char type_text[256]={0};
    char cat[512],sch[512],tab[512];
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;
    cs_arg_text(cat,sizeof(cat),catalog,catalog_len);
    cs_arg_text(sch,sizeof(sch),schema,schema_len);
    cs_arg_text(tab,sizeof(tab),table,table_len);
    cs_arg_text(type_text,sizeof(type_text),types,types_len);
    /* The three ODBC discovery special cases. */
    if(!strcmp(cat,"%")&&!sch[0]&&!tab[0])return cs_tables_catalog_list(s);
    if(!cat[0]&&!strcmp(sch,"%")&&!tab[0])
        return cs_empty_metadata(statement,"NULL TABLE_CAT,NULL TABLE_SCHEM,NULL TABLE_NAME,NULL TABLE_TYPE,NULL REMARKS");
    if(!cat[0]&&!sch[0]&&!tab[0]&&!strcmp(type_text,"%")){
        q=cs_query_alloc(512);
        if(!q)return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");
        snprintf(q,512,"SELECT NULL TABLE_CAT,NULL TABLE_SCHEM,NULL TABLE_NAME,'TABLE' TABLE_TYPE,NULL REMARKS"
                       " UNION ALL SELECT NULL,NULL,NULL,'VIEW',NULL");
        return cs_meta_exec(s,q);
    }
    if(!cs_catalog_matches(s,catalog,catalog_len))
        return cs_empty_metadata(statement,"NULL TABLE_CAT,NULL TABLE_SCHEM,NULL TABLE_NAME,NULL TABLE_TYPE,NULL REMARKS");
    if(type_text[0]){
        if(strstr(type_text,"VIEW")&&!strstr(type_text,"TABLE"))type_filter="type='view'";
        else if(strstr(type_text,"TABLE")&&!strstr(type_text,"VIEW"))type_filter="type='table'";
    }
    pat=cs_sql_literal(table,table_len,"%");q=cs_query_alloc(4096);if(!pat||!q){free(pat);free(q);return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");}
    cs_literal_or_null(cat,sizeof(cat),s->dbc->database);
    snprintf(q,4096,"SELECT %s AS TABLE_CAT,NULL AS TABLE_SCHEM,name AS TABLE_NAME,CASE type WHEN 'view' THEN 'VIEW' ELSE 'TABLE' END AS TABLE_TYPE,NULL AS REMARKS FROM sqlite_master WHERE %s AND name LIKE %s ESCAPE '\\' AND name NOT LIKE 'sqlite_%%' ORDER BY TABLE_TYPE,TABLE_NAME",
             cat,type_filter,pat);
    free(pat);return cs_meta_exec(s,q);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLTables(SQLHSTMT statement,SQLCHAR *catalog,SQLSMALLINT catalog_len,
    SQLCHAR *schema,SQLSMALLINT schema_len,SQLCHAR *table,SQLSMALLINT table_len,
    SQLCHAR *types,SQLSMALLINT types_len) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLTables(statement, catalog, catalog_len, schema, schema_len, table, table_len, types, types_len);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLColumns(SQLHSTMT statement,SQLCHAR *catalog,SQLSMALLINT catalog_len,
    SQLCHAR *schema,SQLSMALLINT schema_len,SQLCHAR *table,SQLSMALLINT table_len,
    SQLCHAR *column,SQLSMALLINT column_len){
    cs_stmt *s=(cs_stmt *)statement;char *tp,*cp,*q;const char *dtype=
        "CASE WHEN upper(p.type) LIKE '%INT%' THEN -5 WHEN upper(p.type) LIKE '%CHAR%' OR upper(p.type) LIKE '%CLOB%' OR upper(p.type) LIKE '%TEXT%' THEN 12 WHEN upper(p.type) LIKE '%BLOB%' OR p.type='' THEN -4 WHEN upper(p.type) LIKE '%REAL%' OR upper(p.type) LIKE '%FLOA%' OR upper(p.type) LIKE '%DOUB%' THEN 8 WHEN upper(p.type) LIKE '%BOOL%' THEN -7 WHEN upper(p.type) LIKE '%TIMESTAMP%' OR upper(p.type) LIKE '%DATETIME%' THEN 93 WHEN upper(p.type)='DATE' THEN 91 WHEN upper(p.type)='TIME' THEN 92 ELSE 12 END";
    char cat[512];
    (void)schema;(void)schema_len;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;
    if(!cs_catalog_matches(s,catalog,catalog_len))
        return cs_empty_metadata(statement,"NULL TABLE_CAT,NULL TABLE_SCHEM,NULL TABLE_NAME,NULL COLUMN_NAME,NULL DATA_TYPE,NULL TYPE_NAME,NULL COLUMN_SIZE,NULL BUFFER_LENGTH,NULL DECIMAL_DIGITS,NULL NUM_PREC_RADIX,NULL NULLABLE,NULL REMARKS,NULL COLUMN_DEF,NULL SQL_DATA_TYPE,NULL SQL_DATETIME_SUB,NULL CHAR_OCTET_LENGTH,NULL ORDINAL_POSITION,NULL IS_NULLABLE");
    cs_literal_or_null(cat,sizeof(cat),s->dbc->database);
    tp=cs_sql_literal(table,table_len,"%");cp=cs_sql_literal(column,column_len,"%");q=cs_query_alloc(16384);if(!tp||!cp||!q){free(tp);free(cp);free(q);return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");}
    snprintf(q,16384,"SELECT %s TABLE_CAT,NULL TABLE_SCHEM,m.name TABLE_NAME,p.name COLUMN_NAME,%s DATA_TYPE,CASE WHEN p.type='' THEN 'BLOB' ELSE upper(p.type) END TYPE_NAME,CASE WHEN %s IN (-5) THEN 19 WHEN %s IN (8) THEN 15 WHEN %s IN (91) THEN 10 WHEN %s IN (92) THEN 8 WHEN %s IN (93) THEN 29 ELSE 65535 END COLUMN_SIZE,NULL BUFFER_LENGTH,NULL DECIMAL_DIGITS,CASE WHEN %s IN (-5,8) THEN 10 ELSE NULL END NUM_PREC_RADIX,CASE p.[notnull] WHEN 1 THEN 0 ELSE 1 END NULLABLE,NULL REMARKS,p.dflt_value COLUMN_DEF,%s SQL_DATA_TYPE,NULL SQL_DATETIME_SUB,CASE WHEN %s IN (12) THEN 65535 ELSE NULL END CHAR_OCTET_LENGTH,p.cid+1 ORDINAL_POSITION,CASE p.[notnull] WHEN 1 THEN 'NO' ELSE 'YES' END IS_NULLABLE FROM sqlite_master m JOIN pragma_table_info(m.name) p WHERE m.type IN ('table','view') AND m.name LIKE %s ESCAPE '\\' AND p.name LIKE %s ESCAPE '\\' ORDER BY m.name,p.cid",cat,dtype,dtype,dtype,dtype,dtype,dtype,dtype,dtype,dtype,tp,cp);
    free(tp);free(cp);return cs_meta_exec(s,q);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLColumns(SQLHSTMT statement,SQLCHAR *catalog,SQLSMALLINT catalog_len,
    SQLCHAR *schema,SQLSMALLINT schema_len,SQLCHAR *table,SQLSMALLINT table_len,
    SQLCHAR *column,SQLSMALLINT column_len) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLColumns(statement, catalog, catalog_len, schema, schema_len, table, table_len, column, column_len);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLPrimaryKeys(SQLHSTMT statement,SQLCHAR *catalog,SQLSMALLINT catalog_len,
    SQLCHAR *schema,SQLSMALLINT schema_len,SQLCHAR *table,SQLSMALLINT table_len){
    cs_stmt *s=(cs_stmt *)statement;char *tp,*q;char cat[512];(void)schema;(void)schema_len;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;
    if(!cs_catalog_matches(s,catalog,catalog_len))
        return cs_empty_metadata(statement,"NULL TABLE_CAT,NULL TABLE_SCHEM,NULL TABLE_NAME,NULL COLUMN_NAME,NULL KEY_SEQ,NULL PK_NAME");
    cs_literal_or_null(cat,sizeof(cat),s->dbc->database);
    tp=cs_sql_literal(table,table_len,"");q=cs_query_alloc(4096);if(!tp||!q){free(tp);free(q);return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");}
    snprintf(q,4096,"SELECT %s TABLE_CAT,NULL TABLE_SCHEM,%s TABLE_NAME,p.name COLUMN_NAME,p.pk KEY_SEQ,'PRIMARY' PK_NAME FROM pragma_table_info(%s) p WHERE p.pk>0 ORDER BY p.pk",cat,tp,tp);free(tp);return cs_meta_exec(s,q);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLPrimaryKeys(SQLHSTMT statement,SQLCHAR *catalog,SQLSMALLINT catalog_len,
    SQLCHAR *schema,SQLSMALLINT schema_len,SQLCHAR *table,SQLSMALLINT table_len) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLPrimaryKeys(statement, catalog, catalog_len, schema, schema_len, table, table_len);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLForeignKeys(SQLHSTMT statement,
    SQLCHAR *pkcat,SQLSMALLINT pkcat_len,SQLCHAR *pkschema,SQLSMALLINT pkschema_len,SQLCHAR *pktable,SQLSMALLINT pktable_len,
    SQLCHAR *fkcat,SQLSMALLINT fkcat_len,SQLCHAR *fkschema,SQLSMALLINT fkschema_len,SQLCHAR *fktable,SQLSMALLINT fktable_len){
    cs_stmt *s=(cs_stmt *)statement;char *pp,*fp,*q;(void)pkcat;(void)pkcat_len;(void)pkschema;(void)pkschema_len;(void)fkcat;(void)fkcat_len;(void)fkschema;(void)fkschema_len;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;pp=cs_sql_literal(pktable,pktable_len,"%");fp=cs_sql_literal(fktable,fktable_len,"%");q=cs_query_alloc(8192);if(!pp||!fp||!q){free(pp);free(fp);free(q);return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");}
    snprintf(q,8192,"SELECT NULL PKTABLE_CAT,NULL PKTABLE_SCHEM,f.[table] PKTABLE_NAME,f.[to] PKCOLUMN_NAME,NULL FKTABLE_CAT,NULL FKTABLE_SCHEM,m.name FKTABLE_NAME,f.[from] FKCOLUMN_NAME,f.seq+1 KEY_SEQ,CASE f.on_update WHEN 'CASCADE' THEN 0 WHEN 'RESTRICT' THEN 1 WHEN 'SET NULL' THEN 2 WHEN 'NO ACTION' THEN 3 WHEN 'SET DEFAULT' THEN 4 ELSE 3 END UPDATE_RULE,CASE f.on_delete WHEN 'CASCADE' THEN 0 WHEN 'RESTRICT' THEN 1 WHEN 'SET NULL' THEN 2 WHEN 'NO ACTION' THEN 3 WHEN 'SET DEFAULT' THEN 4 ELSE 3 END DELETE_RULE,NULL FK_NAME,'PRIMARY' PK_NAME,7 DEFERRABILITY FROM sqlite_master m JOIN pragma_foreign_key_list(m.name) f WHERE m.type='table' AND f.[table] LIKE %s ESCAPE '\\' AND m.name LIKE %s ESCAPE '\\' ORDER BY m.name,f.id,f.seq",pp,fp);free(pp);free(fp);return cs_meta_exec(s,q);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLForeignKeys(SQLHSTMT statement,
    SQLCHAR *pkcat,SQLSMALLINT pkcat_len,SQLCHAR *pkschema,SQLSMALLINT pkschema_len,SQLCHAR *pktable,SQLSMALLINT pktable_len,
    SQLCHAR *fkcat,SQLSMALLINT fkcat_len,SQLCHAR *fkschema,SQLSMALLINT fkschema_len,SQLCHAR *fktable,SQLSMALLINT fktable_len) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLForeignKeys(statement, pkcat, pkcat_len, pkschema, pkschema_len, pktable, pktable_len, fkcat, fkcat_len, fkschema, fkschema_len, fktable, fktable_len);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLStatistics(SQLHSTMT statement,SQLCHAR *catalog,SQLSMALLINT catalog_len,
    SQLCHAR *schema,SQLSMALLINT schema_len,SQLCHAR *table,SQLSMALLINT table_len,SQLUSMALLINT unique,SQLUSMALLINT reserved){
    cs_stmt *s=(cs_stmt *)statement;char *tp,*q;const char *uf=unique==SQL_INDEX_UNIQUE?"AND il.[unique]=1":"";(void)catalog;(void)catalog_len;(void)schema;(void)schema_len;(void)reserved;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;tp=cs_sql_literal(table,table_len,"");q=cs_query_alloc(8192);if(!tp||!q){free(tp);free(q);return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");}
    snprintf(q,8192,"SELECT NULL TABLE_CAT,NULL TABLE_SCHEM,%s TABLE_NAME,CASE il.[unique] WHEN 1 THEN 0 ELSE 1 END NON_UNIQUE,NULL INDEX_QUALIFIER,il.name INDEX_NAME,3 TYPE,ii.seqno+1 ORDINAL_POSITION,ii.name COLUMN_NAME,NULL ASC_OR_DESC,NULL CARDINALITY,NULL PAGES,NULL FILTER_CONDITION FROM pragma_index_list(%s) il JOIN pragma_index_info(il.name) ii WHERE 1=1 %s ORDER BY NON_UNIQUE,INDEX_NAME,ORDINAL_POSITION",tp,tp,uf);free(tp);return cs_meta_exec(s,q);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLStatistics(SQLHSTMT statement,SQLCHAR *catalog,SQLSMALLINT catalog_len,
    SQLCHAR *schema,SQLSMALLINT schema_len,SQLCHAR *table,SQLSMALLINT table_len,SQLUSMALLINT unique,SQLUSMALLINT reserved) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLStatistics(statement, catalog, catalog_len, schema, schema_len, table, table_len, unique, reserved);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLSpecialColumns(SQLHSTMT statement,SQLUSMALLINT identifier,
    SQLCHAR *catalog,SQLSMALLINT catalog_len,SQLCHAR *schema,SQLSMALLINT schema_len,
    SQLCHAR *table,SQLSMALLINT table_len,SQLUSMALLINT scope,SQLUSMALLINT nullable){
    cs_stmt *s=(cs_stmt *)statement;char *q;(void)catalog;(void)catalog_len;(void)schema;(void)schema_len;(void)table;(void)table_len;(void)scope;(void)nullable;
    if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;q=cs_query_alloc(1024);if(!q)return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");
    if(identifier==SQL_BEST_ROWID)strcpy(q,"SELECT 2 SCOPE,'rowid' COLUMN_NAME,-5 DATA_TYPE,'BIGINT' TYPE_NAME,19 COLUMN_SIZE,8 BUFFER_LENGTH,0 DECIMAL_DIGITS,2 PSEUDO_COLUMN");
    else strcpy(q,"SELECT NULL SCOPE,NULL COLUMN_NAME,NULL DATA_TYPE,NULL TYPE_NAME,NULL COLUMN_SIZE,NULL BUFFER_LENGTH,NULL DECIMAL_DIGITS,NULL PSEUDO_COLUMN WHERE 0");return cs_meta_exec(s,q);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLSpecialColumns(SQLHSTMT statement,SQLUSMALLINT identifier,
    SQLCHAR *catalog,SQLSMALLINT catalog_len,SQLCHAR *schema,SQLSMALLINT schema_len,
    SQLCHAR *table,SQLSMALLINT table_len,SQLUSMALLINT scope,SQLUSMALLINT nullable) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSpecialColumns(statement, identifier, catalog, catalog_len, schema, schema_len, table, table_len, scope, nullable);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetTypeInfo(SQLHSTMT statement,SQLSMALLINT requested){
    cs_stmt *s=(cs_stmt *)statement;char *q;const char *filter="";char f[64];if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;
    if(requested!=SQL_ALL_TYPES){snprintf(f,sizeof(f)," WHERE DATA_TYPE=%d",requested);filter=f;}q=cs_query_alloc(16384);if(!q)return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");
    snprintf(q,16384,"SELECT * FROM (SELECT 'VARCHAR' TYPE_NAME,12 DATA_TYPE,65535 COLUMN_SIZE,'''' LITERAL_PREFIX,'''' LITERAL_SUFFIX,'length' CREATE_PARAMS,1 NULLABLE,1 CASE_SENSITIVE,3 SEARCHABLE,0 UNSIGNED_ATTRIBUTE,0 FIXED_PREC_SCALE,0 AUTO_UNIQUE_VALUE,'VARCHAR' LOCAL_TYPE_NAME,NULL MINIMUM_SCALE,NULL MAXIMUM_SCALE,12 SQL_DATA_TYPE,NULL SQL_DATETIME_SUB,10 NUM_PREC_RADIX UNION ALL SELECT 'LONGVARCHAR',-1,2147483647,'''','''',NULL,1,1,3,0,0,0,'LONGVARCHAR',NULL,NULL,-1,NULL,10 UNION ALL SELECT 'BIGINT',-5,19,NULL,NULL,NULL,1,0,3,0,0,0,'BIGINT',0,0,-5,NULL,10 UNION ALL SELECT 'DOUBLE',8,15,NULL,NULL,NULL,1,0,3,0,0,0,'DOUBLE',0,0,8,NULL,2 UNION ALL SELECT 'DECIMAL',3,19,NULL,NULL,'precision,scale',1,0,3,0,0,0,'DECIMAL',0,15,3,NULL,10 UNION ALL SELECT 'BIT',-7,1,NULL,NULL,NULL,1,0,3,0,0,0,'BIT',0,0,-7,NULL,2 UNION ALL SELECT 'LONGVARBINARY',-4,2147483647,'X''','''',NULL,1,0,3,0,0,0,'LONGVARBINARY',NULL,NULL,-4,NULL,2 UNION ALL SELECT 'DATE',91,10,'DATE ''','''',NULL,1,0,3,0,0,0,'DATE',0,0,9,1,10 UNION ALL SELECT 'TIME',92,8,'TIME ''','''',NULL,1,0,3,0,0,0,'TIME',0,0,9,2,10 UNION ALL SELECT 'TIMESTAMP',93,29,'TIMESTAMP ''','''',NULL,1,0,3,0,0,0,'TIMESTAMP',0,9,9,3,10)%s ORDER BY DATA_TYPE",filter);return cs_meta_exec(s,q);
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetTypeInfo(SQLHSTMT statement,SQLSMALLINT requested) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetTypeInfo(statement, requested);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN cs_empty_metadata(SQLHSTMT statement,const char *columns){cs_stmt *s=(cs_stmt *)statement;size_t cap=strlen(columns)+32;char *q;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;q=cs_query_alloc(cap);if(!q)return cs_diag_add(&s->h,"HY001",0,"Memory allocation error");snprintf(q,cap,"SELECT %s WHERE 0",columns);return cs_meta_exec(s,q);}

static SQLRETURN SQL_API cs_i_SQLProcedures(SQLHSTMT s,SQLCHAR*a,SQLSMALLINT b,SQLCHAR*c,SQLSMALLINT d,SQLCHAR*e,SQLSMALLINT f){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;return cs_empty_metadata(s,"NULL PROCEDURE_CAT,NULL PROCEDURE_SCHEM,NULL PROCEDURE_NAME,NULL NUM_INPUT_PARAMS,NULL NUM_OUTPUT_PARAMS,NULL NUM_RESULT_SETS,NULL REMARKS,NULL PROCEDURE_TYPE");}

CSODBC_EXPORT SQLRETURN SQL_API SQLProcedures(SQLHSTMT s,SQLCHAR*a,SQLSMALLINT b,SQLCHAR*c,SQLSMALLINT d,SQLCHAR*e,SQLSMALLINT f) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLProcedures(s, a, b, c, d, e, f);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLProcedureColumns(SQLHSTMT s,SQLCHAR*a,SQLSMALLINT b,SQLCHAR*c,SQLSMALLINT d,SQLCHAR*e,SQLSMALLINT f,SQLCHAR*g,SQLSMALLINT h){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;return cs_empty_metadata(s,"NULL PROCEDURE_CAT,NULL PROCEDURE_SCHEM,NULL PROCEDURE_NAME,NULL COLUMN_NAME,NULL COLUMN_TYPE,NULL DATA_TYPE,NULL TYPE_NAME,NULL COLUMN_SIZE,NULL BUFFER_LENGTH,NULL DECIMAL_DIGITS,NULL NUM_PREC_RADIX,NULL NULLABLE,NULL REMARKS,NULL COLUMN_DEF,NULL SQL_DATA_TYPE,NULL SQL_DATETIME_SUB,NULL CHAR_OCTET_LENGTH,NULL ORDINAL_POSITION,NULL IS_NULLABLE");}

CSODBC_EXPORT SQLRETURN SQL_API SQLProcedureColumns(SQLHSTMT s,SQLCHAR*a,SQLSMALLINT b,SQLCHAR*c,SQLSMALLINT d,SQLCHAR*e,SQLSMALLINT f,SQLCHAR*g,SQLSMALLINT h) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLProcedureColumns(s, a, b, c, d, e, f, g, h);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLColumnPrivileges(SQLHSTMT s,SQLCHAR*a,SQLSMALLINT b,SQLCHAR*c,SQLSMALLINT d,SQLCHAR*e,SQLSMALLINT f,SQLCHAR*g,SQLSMALLINT h){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;return cs_empty_metadata(s,"NULL TABLE_CAT,NULL TABLE_SCHEM,NULL TABLE_NAME,NULL COLUMN_NAME,NULL GRANTOR,NULL GRANTEE,NULL PRIVILEGE,NULL IS_GRANTABLE");}

CSODBC_EXPORT SQLRETURN SQL_API SQLColumnPrivileges(SQLHSTMT s,SQLCHAR*a,SQLSMALLINT b,SQLCHAR*c,SQLSMALLINT d,SQLCHAR*e,SQLSMALLINT f,SQLCHAR*g,SQLSMALLINT h) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLColumnPrivileges(s, a, b, c, d, e, f, g, h);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLTablePrivileges(SQLHSTMT s,SQLCHAR*a,SQLSMALLINT b,SQLCHAR*c,SQLSMALLINT d,SQLCHAR*e,SQLSMALLINT f){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;return cs_empty_metadata(s,"NULL TABLE_CAT,NULL TABLE_SCHEM,NULL TABLE_NAME,NULL GRANTOR,NULL GRANTEE,NULL PRIVILEGE,NULL IS_GRANTABLE");}

CSODBC_EXPORT SQLRETURN SQL_API SQLTablePrivileges(SQLHSTMT s,SQLCHAR*a,SQLSMALLINT b,SQLCHAR*c,SQLSMALLINT d,SQLCHAR*e,SQLSMALLINT f) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLTablePrivileges(s, a, b, c, d, e, f);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN cs_info_string(cs_dbc *dbc,SQLPOINTER out,SQLSMALLINT cap,SQLSMALLINT *len,const char *value){SQLLEN n=0;SQLRETURN rc=cs_copy_utf8((SQLCHAR *)out,cap,&n,value,&dbc->h);if(len)*len=(SQLSMALLINT)n;return rc;}
static SQLRETURN cs_info_u16(SQLPOINTER out,SQLSMALLINT *len,SQLUSMALLINT value){if(out)*(SQLUSMALLINT *)out=value;if(len)*len=sizeof(value);return SQL_SUCCESS;}
static SQLRETURN cs_info_u32(SQLPOINTER out,SQLSMALLINT *len,SQLUINTEGER value){if(out)*(SQLUINTEGER *)out=value;if(len)*len=sizeof(value);return SQL_SUCCESS;}

static SQLRETURN SQL_API cs_i_SQLGetInfo(SQLHDBC connection,SQLUSMALLINT type,
    SQLPOINTER out,SQLSMALLINT capacity,SQLSMALLINT *length){
    cs_dbc *d=(cs_dbc *)connection;if(!cs_valid_handle(connection,SQL_HANDLE_DBC))return SQL_INVALID_HANDLE;cs_diag_clear(&d->h);
    switch(type){
        case SQL_DATA_SOURCE_NAME:return cs_info_string(d,out,capacity,length,d->dsn);case SQL_SERVER_NAME:return cs_info_string(d,out,capacity,length,d->host);
        case SQL_USER_NAME:return cs_info_string(d,out,capacity,length,d->user);case SQL_DATABASE_NAME:return cs_info_string(d,out,capacity,length,d->database);
        case SQL_DRIVER_NAME:return cs_info_string(d,out,capacity,length,"cubesqlodbc.dll");case SQL_DRIVER_VER:return cs_info_string(d,out,capacity,length,CSODBC_VERSION);
        case SQL_ODBC_VER:return cs_info_string(d,out,capacity,length,CSODBC_ODBC_VERSION);case SQL_DRIVER_ODBC_VER:return cs_info_string(d,out,capacity,length,CSODBC_DRIVER_ODBC_VERSION);case SQL_DBMS_NAME:return cs_info_string(d,out,capacity,length,"CubeSQL");
        case SQL_DBMS_VER:return cs_info_string(d,out,capacity,length,d->dbms_version[0]?d->dbms_version:"00.00.0000");case SQL_IDENTIFIER_QUOTE_CHAR:return cs_info_string(d,out,capacity,length,"\"");
        case SQL_SEARCH_PATTERN_ESCAPE:return cs_info_string(d,out,capacity,length,"\\");case SQL_CATALOG_NAME_SEPARATOR:return cs_info_string(d,out,capacity,length,".");
        case SQL_CATALOG_TERM:return cs_info_string(d,out,capacity,length,"database");case SQL_SCHEMA_TERM:return cs_info_string(d,out,capacity,length,"");
        case SQL_TABLE_TERM:return cs_info_string(d,out,capacity,length,"table");case SQL_PROCEDURE_TERM:return cs_info_string(d,out,capacity,length,"");
        case SQL_SPECIAL_CHARACTERS:return cs_info_string(d,out,capacity,length,"_\"");case SQL_DATA_SOURCE_READ_ONLY:return cs_info_string(d,out,capacity,length,d->access_mode==SQL_MODE_READ_ONLY?"Y":"N");
        case SQL_ACCESSIBLE_TABLES:return cs_info_string(d,out,capacity,length,"Y");case SQL_ACCESSIBLE_PROCEDURES:return cs_info_string(d,out,capacity,length,"N");
        case SQL_PROCEDURES:return cs_info_string(d,out,capacity,length,"N");case SQL_ROW_UPDATES:return cs_info_string(d,out,capacity,length,"N");
        case SQL_MULT_RESULT_SETS:return cs_info_string(d,out,capacity,length,"N");case SQL_MULTIPLE_ACTIVE_TXN:return cs_info_string(d,out,capacity,length,"N");
        case SQL_OUTER_JOINS:return cs_info_string(d,out,capacity,length,"Y");case SQL_EXPRESSIONS_IN_ORDERBY:return cs_info_string(d,out,capacity,length,"Y");
        case SQL_ORDER_BY_COLUMNS_IN_SELECT:return cs_info_string(d,out,capacity,length,"N");case SQL_LIKE_ESCAPE_CLAUSE:return cs_info_string(d,out,capacity,length,"Y");
        case SQL_NEED_LONG_DATA_LEN:return cs_info_string(d,out,capacity,length,"N");case SQL_CATALOG_NAME:return cs_info_string(d,out,capacity,length,"Y");
        case SQL_MAX_DRIVER_CONNECTIONS:case SQL_MAX_CONCURRENT_ACTIVITIES:case SQL_MAX_COLUMN_NAME_LEN:case SQL_MAX_TABLE_NAME_LEN:case SQL_MAX_CATALOG_NAME_LEN:case SQL_MAX_SCHEMA_NAME_LEN:case SQL_MAX_CURSOR_NAME_LEN:case SQL_MAX_USER_NAME_LEN:case SQL_MAX_IDENTIFIER_LEN:return cs_info_u16(out,length,0);
        case SQL_ODBC_API_CONFORMANCE:return cs_info_u16(out,length,SQL_OAC_LEVEL1);case SQL_ODBC_SAG_CLI_CONFORMANCE:return cs_info_u16(out,length,SQL_OSCC_COMPLIANT);
        case SQL_ODBC_SQL_CONFORMANCE:return cs_info_u16(out,length,SQL_OSC_CORE);case SQL_SQL_CONFORMANCE:return cs_info_u32(out,length,SQL_SC_SQL92_ENTRY);
        case SQL_IDENTIFIER_CASE:return cs_info_u16(out,length,SQL_IC_MIXED);case SQL_QUOTED_IDENTIFIER_CASE:return cs_info_u16(out,length,SQL_IC_SENSITIVE);
        case SQL_CURSOR_COMMIT_BEHAVIOR:case SQL_CURSOR_ROLLBACK_BEHAVIOR:return cs_info_u16(out,length,SQL_CB_PRESERVE);
        case SQL_TXN_CAPABLE:return cs_info_u16(out,length,SQL_TC_ALL);case SQL_DEFAULT_TXN_ISOLATION:return cs_info_u32(out,length,SQL_TXN_SERIALIZABLE);
        case SQL_TXN_ISOLATION_OPTION:return cs_info_u32(out,length,SQL_TXN_SERIALIZABLE);case SQL_SCROLL_OPTIONS:return cs_info_u32(out,length,SQL_SO_FORWARD_ONLY|SQL_SO_STATIC);
        case SQL_GETDATA_EXTENSIONS:return cs_info_u32(out,length,SQL_GD_ANY_COLUMN|SQL_GD_ANY_ORDER|SQL_GD_BLOCK);case SQL_NULL_COLLATION:return cs_info_u16(out,length,SQL_NC_LOW);
        case SQL_CATALOG_LOCATION:return cs_info_u16(out,length,SQL_CL_START);case SQL_ASYNC_MODE:return cs_info_u32(out,length,SQL_AM_NONE);
        case SQL_PARAM_ARRAY_ROW_COUNTS:return cs_info_u32(out,length,SQL_PARC_NO_BATCH);case SQL_PARAM_ARRAY_SELECTS:return cs_info_u32(out,length,SQL_PAS_NO_SELECT);
        case SQL_BATCH_SUPPORT:return cs_info_u32(out,length,0);case SQL_DESCRIBE_PARAMETER:return cs_info_string(d,out,capacity,length,"Y");
        case SQL_MAX_COLUMNS_IN_GROUP_BY:case SQL_MAX_COLUMNS_IN_INDEX:case SQL_MAX_COLUMNS_IN_ORDER_BY:case SQL_MAX_COLUMNS_IN_SELECT:case SQL_MAX_COLUMNS_IN_TABLE:case SQL_MAX_TABLES_IN_SELECT:return cs_info_u16(out,length,0);
        case SQL_MAX_INDEX_SIZE:case SQL_MAX_ROW_SIZE:case SQL_MAX_STATEMENT_LEN:case SQL_MAX_CHAR_LITERAL_LEN:case SQL_MAX_BINARY_LITERAL_LEN:return cs_info_u32(out,length,0);
        case SQL_MAX_ROW_SIZE_INCLUDES_LONG:return cs_info_string(d,out,capacity,length,"Y");
        case SQL_ALTER_TABLE:return cs_info_u32(out,length,SQL_AT_ADD_COLUMN|SQL_AT_DROP_COLUMN);case SQL_CONCAT_NULL_BEHAVIOR:return cs_info_u16(out,length,SQL_CB_NULL);

        /*
         * Everything below completes the ODBC 3.x InfoType set. Returning
         * HY096 for these made consumers such as Excel, Access and ADO abort
         * as soon as they interrogated the driver. The values describe what
         * this driver genuinely does, not what would look best.
         */
        case SQL_ACTIVE_ENVIRONMENTS:return cs_info_u16(out,length,0);
        case SQL_MAX_ASYNC_CONCURRENT_STATEMENTS:return cs_info_u32(out,length,0);
        case SQL_MAX_PROCEDURE_NAME_LEN:return cs_info_u16(out,length,0);
        case SQL_AGGREGATE_FUNCTIONS:
            return cs_info_u32(out,length,SQL_AF_ALL|SQL_AF_AVG|SQL_AF_COUNT|SQL_AF_DISTINCT|SQL_AF_MAX|SQL_AF_MIN|SQL_AF_SUM);
        case SQL_ALTER_DOMAIN:return cs_info_u32(out,length,0);
        case SQL_BATCH_ROW_COUNT:return cs_info_u32(out,length,0);
        case SQL_BOOKMARK_PERSISTENCE:return cs_info_u32(out,length,0);
        /*
         * Zero, and it needs to stay zero: a CubeSQL table cannot be qualified
         * with the database it lives in. The database is chosen per connection
         * with USE DATABASE, and there is no catalog.table syntax to fall back
         * on - a catalog name here normally ends in ".sdb", so it carries the
         * separator itself and could not be parsed as a qualifier anyway.
         *
         * Claiming SQL_CU_DML_STATEMENTS told consumers the opposite. Excel
         * took that, SQL_CATALOG_LOCATION (start), the separator (".") and the
         * TABLE_CAT that SQLTables reports, and issued
         *     SELECT * FROM "Travel.sdb"."BELEGART"
         * which the server rejects with native error 7009, "no such table".
         * Every table of every database failed that way, so the driver was
         * unusable from Excel while looking perfectly healthy.
         *
         * The catalog is still reported: SQLTables lists the databases and
         * names the one each table belongs to, which is what lets a consumer
         * show them. It simply cannot be written into a statement.
         */
        case SQL_CATALOG_USAGE:return cs_info_u32(out,length,0);
        case SQL_SCHEMA_USAGE:return cs_info_u32(out,length,0);
        case SQL_COLLATION_SEQ:return cs_info_string(d,out,capacity,length,"");
        case SQL_COLUMN_ALIAS:return cs_info_string(d,out,capacity,length,"Y");
        case SQL_CORRELATION_NAME:return cs_info_u16(out,length,SQL_CN_ANY);
        case SQL_CURSOR_SENSITIVITY:return cs_info_u32(out,length,SQL_INSENSITIVE);
        case SQL_DATETIME_LITERALS:return cs_info_u32(out,length,0);
        case SQL_DDL_INDEX:return cs_info_u32(out,length,SQL_DI_CREATE_INDEX|SQL_DI_DROP_INDEX);
        case SQL_INDEX_KEYWORDS:return cs_info_u32(out,length,SQL_IK_ASC|SQL_IK_DESC);
        case SQL_INFO_SCHEMA_VIEWS:return cs_info_u32(out,length,0);
        case SQL_INSERT_STATEMENT:
            return cs_info_u32(out,length,SQL_IS_INSERT_LITERALS|SQL_IS_INSERT_SEARCHED|SQL_IS_SELECT_INTO);
        case SQL_INTEGRITY:return cs_info_string(d,out,capacity,length,"N");
        case SQL_NON_NULLABLE_COLUMNS:return cs_info_u16(out,length,SQL_NNC_NON_NULL);
        case SQL_ODBC_INTERFACE_CONFORMANCE:return cs_info_u32(out,length,SQL_OIC_CORE);
        case SQL_STANDARD_CLI_CONFORMANCE:return cs_info_u32(out,length,SQL_SCC_XOPEN_CLI_VERSION1);
        case SQL_XOPEN_CLI_YEAR:return cs_info_string(d,out,capacity,length,"1995");
        case SQL_OJ_CAPABILITIES:
            return cs_info_u32(out,length,SQL_OJ_LEFT|SQL_OJ_INNER|SQL_OJ_NOT_ORDERED|SQL_OJ_ALL_COMPARISON_OPS);
        case SQL_GROUP_BY:return cs_info_u16(out,length,SQL_GB_GROUP_BY_CONTAINS_SELECT);
        case SQL_SUBQUERIES:
            return cs_info_u32(out,length,SQL_SQ_CORRELATED_SUBQUERIES|SQL_SQ_COMPARISON|SQL_SQ_EXISTS|SQL_SQ_IN|SQL_SQ_QUANTIFIED);
        case SQL_UNION:return cs_info_u32(out,length,SQL_U_UNION|SQL_U_UNION_ALL);
        case SQL_FILE_USAGE:return cs_info_u16(out,length,SQL_FILE_NOT_SUPPORTED);
        /* Only forward-only and static cursors exist, and both are read-only. */
        case SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES1:return cs_info_u32(out,length,SQL_CA1_NEXT);
        case SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES2:
            return cs_info_u32(out,length,SQL_CA2_READ_ONLY_CONCURRENCY|SQL_CA2_CRC_EXACT);
        case SQL_STATIC_CURSOR_ATTRIBUTES1:
            return cs_info_u32(out,length,SQL_CA1_NEXT|SQL_CA1_ABSOLUTE|SQL_CA1_RELATIVE);
        case SQL_STATIC_CURSOR_ATTRIBUTES2:
            return cs_info_u32(out,length,SQL_CA2_READ_ONLY_CONCURRENCY|SQL_CA2_CRC_EXACT);
        case SQL_DYNAMIC_CURSOR_ATTRIBUTES1:case SQL_DYNAMIC_CURSOR_ATTRIBUTES2:
        case SQL_KEYSET_CURSOR_ATTRIBUTES1:case SQL_KEYSET_CURSOR_ATTRIBUTES2:
            return cs_info_u32(out,length,0);
        case SQL_SCROLL_CONCURRENCY:return cs_info_u32(out,length,SQL_SCCO_READ_ONLY);
        case SQL_LOCK_TYPES:return cs_info_u32(out,length,0);
        case SQL_POS_OPERATIONS:return cs_info_u32(out,length,0);
        case SQL_POSITIONED_STATEMENTS:return cs_info_u32(out,length,0);
        case SQL_STATIC_SENSITIVITY:return cs_info_u32(out,length,0);
        /*
         * Scalar functions: exactly the set cs_translate_escapes rewrites, so
         * an application emitting {fn ...} for anything advertised here gets
         * SQL CubeSQL understands.
         */
        case SQL_STRING_FUNCTIONS:
            return cs_info_u32(out,length,SQL_FN_STR_ASCII|SQL_FN_STR_CHAR|SQL_FN_STR_LCASE|
                SQL_FN_STR_LENGTH|SQL_FN_STR_LTRIM|SQL_FN_STR_REPLACE|SQL_FN_STR_RTRIM|
                SQL_FN_STR_SUBSTRING|SQL_FN_STR_UCASE);
        case SQL_NUMERIC_FUNCTIONS:return cs_info_u32(out,length,SQL_FN_NUM_ABS|SQL_FN_NUM_ROUND);
        case SQL_TIMEDATE_FUNCTIONS:
            return cs_info_u32(out,length,SQL_FN_TD_CURDATE|SQL_FN_TD_CURTIME|SQL_FN_TD_NOW);
        case SQL_SYSTEM_FUNCTIONS:return cs_info_u32(out,length,SQL_FN_SYS_IFNULL);
        case SQL_CONVERT_FUNCTIONS:return cs_info_u32(out,length,SQL_FN_CVT_CAST);
        case SQL_TIMEDATE_ADD_INTERVALS:case SQL_TIMEDATE_DIFF_INTERVALS:
            return cs_info_u32(out,length,0);
        /* No ODBC CONVERT scalar: CAST is the only conversion CubeSQL offers. */
        case SQL_CONVERT_BIGINT:case SQL_CONVERT_BINARY:case SQL_CONVERT_BIT:
        case SQL_CONVERT_CHAR:case SQL_CONVERT_DATE:case SQL_CONVERT_DECIMAL:
        case SQL_CONVERT_DOUBLE:case SQL_CONVERT_FLOAT:case SQL_CONVERT_INTEGER:
        case SQL_CONVERT_LONGVARBINARY:case SQL_CONVERT_LONGVARCHAR:case SQL_CONVERT_NUMERIC:
        case SQL_CONVERT_REAL:case SQL_CONVERT_SMALLINT:case SQL_CONVERT_TIME:
        case SQL_CONVERT_TIMESTAMP:case SQL_CONVERT_TINYINT:case SQL_CONVERT_VARBINARY:
        case SQL_CONVERT_VARCHAR:case SQL_CONVERT_WCHAR:case SQL_CONVERT_WLONGVARCHAR:
        case SQL_CONVERT_WVARCHAR:case SQL_CONVERT_GUID:
        case SQL_CONVERT_INTERVAL_DAY_TIME:case SQL_CONVERT_INTERVAL_YEAR_MONTH:
            return cs_info_u32(out,length,0);
        /* DDL: what CubeSQL actually accepts. */
        case SQL_CREATE_TABLE:
            return cs_info_u32(out,length,SQL_CT_CREATE_TABLE|SQL_CT_COLUMN_CONSTRAINT|
                SQL_CT_COLUMN_DEFAULT|SQL_CT_TABLE_CONSTRAINT);
        case SQL_CREATE_VIEW:return cs_info_u32(out,length,SQL_CV_CREATE_VIEW);
        case SQL_DROP_TABLE:return cs_info_u32(out,length,SQL_DT_DROP_TABLE);
        case SQL_DROP_VIEW:return cs_info_u32(out,length,SQL_DV_DROP_VIEW);
        case SQL_CREATE_ASSERTION:case SQL_CREATE_CHARACTER_SET:case SQL_CREATE_COLLATION:
        case SQL_CREATE_DOMAIN:case SQL_CREATE_SCHEMA:case SQL_CREATE_TRANSLATION:
        case SQL_DROP_ASSERTION:case SQL_DROP_CHARACTER_SET:case SQL_DROP_COLLATION:
        case SQL_DROP_DOMAIN:case SQL_DROP_SCHEMA:case SQL_DROP_TRANSLATION:
            return cs_info_u32(out,length,0);
        /* SQL-92 feature bitmasks: this is an entry-level engine. */
        case SQL_SQL92_DATETIME_FUNCTIONS:case SQL_SQL92_FOREIGN_KEY_DELETE_RULE:
        case SQL_SQL92_FOREIGN_KEY_UPDATE_RULE:case SQL_SQL92_GRANT:
        case SQL_SQL92_NUMERIC_VALUE_FUNCTIONS:case SQL_SQL92_REVOKE:
        case SQL_SQL92_ROW_VALUE_CONSTRUCTOR:case SQL_SQL92_STRING_FUNCTIONS:
        case SQL_SQL92_VALUE_EXPRESSIONS:
            return cs_info_u32(out,length,0);
        case SQL_SQL92_PREDICATES:
            return cs_info_u32(out,length,SQL_SP_BETWEEN|SQL_SP_COMPARISON|SQL_SP_EXISTS|
                SQL_SP_IN|SQL_SP_ISNOTNULL|SQL_SP_ISNULL|SQL_SP_LIKE);
        case SQL_SQL92_RELATIONAL_JOIN_OPERATORS:
            return cs_info_u32(out,length,SQL_SRJO_CROSS_JOIN|SQL_SRJO_INNER_JOIN|
                SQL_SRJO_LEFT_OUTER_JOIN|SQL_SRJO_NATURAL_JOIN);
        case SQL_KEYWORDS:
            /* CubeSQL keywords that are not SQL-92 reserved words. */
            return cs_info_string(d,out,capacity,length,
                "ABORT,ATTACH,AUTOINCREMENT,BEFORE,CONFLICT,DATABASE,DETACH,EACH,"
                "EXCLUSIVE,EXPLAIN,FAIL,GLOB,IF,IGNORE,INDEXED,INSTEAD,ISNULL,LIMIT,"
                "NOTNULL,OFFSET,PLAN,PRAGMA,QUERY,RAISE,REGEXP,REINDEX,RENAME,REPLACE,"
                "RETURNING,TEMP,VACUUM,VIRTUAL");
        default:return cs_diag_add(&d->h,"HY096",0,"Unsupported information type %u",type);
    }
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetInfo(SQLHDBC connection,SQLUSMALLINT type,
    SQLPOINTER out,SQLSMALLINT capacity,SQLSMALLINT *length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetInfo(connection, type, out, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetInfoW(SQLHDBC connection,SQLUSMALLINT type,SQLPOINTER out,SQLSMALLINT capacity,SQLSMALLINT *length){
    cs_dbc *d=(cs_dbc *)connection;char temp[2048];SQLSMALLINT n=0;SQLRETURN rc;SQLLEN wn=0;
    if(!cs_valid_handle(connection,SQL_HANDLE_DBC))return SQL_INVALID_HANDLE;
    switch(type){case SQL_DATA_SOURCE_NAME:case SQL_SERVER_NAME:case SQL_USER_NAME:case SQL_DATABASE_NAME:case SQL_DRIVER_NAME:case SQL_DRIVER_VER:case SQL_ODBC_VER:case SQL_DRIVER_ODBC_VER:case SQL_DBMS_NAME:case SQL_DBMS_VER:case SQL_IDENTIFIER_QUOTE_CHAR:case SQL_SEARCH_PATTERN_ESCAPE:case SQL_CATALOG_NAME_SEPARATOR:case SQL_CATALOG_TERM:case SQL_SCHEMA_TERM:case SQL_TABLE_TERM:case SQL_PROCEDURE_TERM:case SQL_SPECIAL_CHARACTERS:case SQL_DATA_SOURCE_READ_ONLY:case SQL_ACCESSIBLE_TABLES:case SQL_ACCESSIBLE_PROCEDURES:case SQL_PROCEDURES:case SQL_ROW_UPDATES:case SQL_MULT_RESULT_SETS:case SQL_MULTIPLE_ACTIVE_TXN:case SQL_OUTER_JOINS:case SQL_EXPRESSIONS_IN_ORDERBY:case SQL_ORDER_BY_COLUMNS_IN_SELECT:case SQL_LIKE_ESCAPE_CLAUSE:case SQL_NEED_LONG_DATA_LEN:case SQL_CATALOG_NAME:case SQL_DESCRIBE_PARAMETER:case SQL_MAX_ROW_SIZE_INCLUDES_LONG:
    case SQL_COLLATION_SEQ:case SQL_COLUMN_ALIAS:case SQL_INTEGRITY:
    case SQL_KEYWORDS:case SQL_XOPEN_CLI_YEAR:
        rc=SQLGetInfo(connection,type,temp,sizeof(temp),&n);if(!SQL_SUCCEEDED(rc))return rc;rc=cs_copy_utf16((SQLWCHAR *)out,capacity/sizeof(SQLWCHAR),&wn,temp,&d->h);if(length)*length=(SQLSMALLINT)(wn*sizeof(SQLWCHAR));return rc;
        default:return SQLGetInfo(connection,type,out,capacity,length);}
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetInfoW(SQLHDBC connection,SQLUSMALLINT type,SQLPOINTER out,SQLSMALLINT capacity,SQLSMALLINT *length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetInfoW(connection, type, out, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetFunctions(SQLHDBC connection,SQLUSMALLINT id,SQLUSMALLINT *supported){
    cs_dbc *d=(cs_dbc *)connection;static const SQLUSMALLINT funcs[]={SQL_API_SQLALLOCCONNECT,SQL_API_SQLALLOCENV,SQL_API_SQLALLOCSTMT,SQL_API_SQLBINDCOL,SQL_API_SQLBINDPARAMETER,SQL_API_SQLCANCEL,SQL_API_SQLCOLATTRIBUTES,SQL_API_SQLCOLUMNS,SQL_API_SQLCONNECT,SQL_API_SQLDESCRIBECOL,SQL_API_SQLDESCRIBEPARAM,SQL_API_SQLDISCONNECT,SQL_API_SQLDRIVERCONNECT,SQL_API_SQLERROR,SQL_API_SQLEXECDIRECT,SQL_API_SQLEXECUTE,SQL_API_SQLEXTENDEDFETCH,SQL_API_SQLFETCH,SQL_API_SQLFOREIGNKEYS,SQL_API_SQLFREECONNECT,SQL_API_SQLFREEENV,SQL_API_SQLFREESTMT,SQL_API_SQLGETCONNECTOPTION,SQL_API_SQLGETDATA,SQL_API_SQLGETFUNCTIONS,SQL_API_SQLGETINFO,SQL_API_SQLGETSTMTOPTION,SQL_API_SQLGETTYPEINFO,SQL_API_SQLMORERESULTS,SQL_API_SQLNATIVESQL,SQL_API_SQLNUMPARAMS,SQL_API_SQLNUMRESULTCOLS,SQL_API_SQLPARAMDATA,SQL_API_SQLPREPARE,SQL_API_SQLPRIMARYKEYS,SQL_API_SQLPUTDATA,SQL_API_SQLROWCOUNT,SQL_API_SQLSETCONNECTOPTION,SQL_API_SQLSETSTMTOPTION,SQL_API_SQLSPECIALCOLUMNS,SQL_API_SQLSTATISTICS,SQL_API_SQLTABLES,SQL_API_SQLTRANSACT,
        /*
         * ODBC 3.x entry points. The list above holds only the 2.x identifiers,
         * so SQLGetFunctions(SQL_API_ODBC3_ALL_FUNCTIONS) used to answer that
         * core ODBC 3 calls - SQLAllocHandle, SQLFreeHandle, SQLGetDiagRec,
         * SQLSetStmtAttr and the rest - were unsupported, even though the driver
         * exports every one of them. While the driver declared itself ODBC 2.0
         * the Driver Manager never asked, so the mistake stayed hidden; as soon
         * as it reported 3.x the Driver Manager believed the answer and faulted
         * inside ODBC32.dll on the first SQLExecDirect.
         *
         * SQLColAttribute shares identifier 6 with SQLColAttributes, already
         * listed above. The descriptor functions are deliberately absent: they
         * genuinely are not implemented, and reporting them missing is correct.
         */
        SQL_API_SQLALLOCHANDLE,SQL_API_SQLFREEHANDLE,SQL_API_SQLCLOSECURSOR,SQL_API_SQLENDTRAN,
        SQL_API_SQLFETCHSCROLL,SQL_API_SQLGETCONNECTATTR,SQL_API_SQLSETCONNECTATTR,
        SQL_API_SQLGETENVATTR,SQL_API_SQLSETENVATTR,SQL_API_SQLGETSTMTATTR,SQL_API_SQLSETSTMTATTR,
        SQL_API_SQLGETDIAGREC,SQL_API_SQLGETDIAGFIELD,SQL_API_SQLBULKOPERATIONS,
        SQL_API_SQLSETPOS};size_t i;
    if(!cs_valid_handle(connection,SQL_HANDLE_DBC))return SQL_INVALID_HANDLE;cs_diag_clear(&d->h);if(!supported)return cs_diag_add(&d->h,"HY009",0,"Supported-functions buffer is null");
    if(id==SQL_API_ODBC3_ALL_FUNCTIONS){memset(supported,0,SQL_API_ODBC3_ALL_FUNCTIONS_SIZE*sizeof(SQLUSMALLINT));for(i=0;i<sizeof(funcs)/sizeof(funcs[0]);i++)supported[funcs[i]>>4]|=(SQLUSMALLINT)(1U<<(funcs[i]&15));return SQL_SUCCESS;}
    if(id==SQL_API_ALL_FUNCTIONS){memset(supported,0,100*sizeof(SQLUSMALLINT));for(i=0;i<sizeof(funcs)/sizeof(funcs[0]);i++)if(funcs[i]<100)supported[funcs[i]]=SQL_TRUE;return SQL_SUCCESS;}
    *supported=SQL_FALSE;for(i=0;i<sizeof(funcs)/sizeof(funcs[0]);i++)if(funcs[i]==id){*supported=SQL_TRUE;break;}return SQL_SUCCESS;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetFunctions(SQLHDBC connection,SQLUSMALLINT id,SQLUSMALLINT *supported) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetFunctions(connection, id, supported);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLNativeSql(SQLHDBC connection,SQLCHAR *input,SQLINTEGER input_len,SQLCHAR *output,SQLINTEGER capacity,SQLINTEGER *output_len){cs_dbc *d=(cs_dbc *)connection;char *u;SQLLEN n=0;SQLRETURN rc;if(!cs_valid_handle(connection,SQL_HANDLE_DBC))return SQL_INVALID_HANDLE;cs_diag_clear(&d->h);if(!input)return cs_diag_add(&d->h,"HY009",0,"SQL text is null");u=cs_strndup0((char *)input,cs_input_len(input,input_len));if(!u)return cs_diag_add(&d->h,"HY001",0,"Memory allocation error");
    {char *t=cs_translate_escapes(u);if(t){free(u);u=t;}}
    rc=cs_copy_utf8(output,capacity,&n,u,&d->h);if(output_len)*output_len=(SQLINTEGER)n;free(u);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLNativeSql(SQLHDBC connection,SQLCHAR *input,SQLINTEGER input_len,SQLCHAR *output,SQLINTEGER capacity,SQLINTEGER *output_len) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLNativeSql(connection, input, input_len, output, capacity, output_len);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLNativeSqlW(SQLHDBC connection,SQLWCHAR *input,SQLINTEGER input_len,SQLWCHAR *output,SQLINTEGER capacity,SQLINTEGER *output_len){cs_dbc*d=(cs_dbc*)connection;char*u;SQLLEN n=0;SQLRETURN rc;if(!cs_valid_handle(connection,SQL_HANDLE_DBC))return SQL_INVALID_HANDLE;cs_diag_clear(&d->h);u=cs_utf16_to_utf8(input,input_len);if(!u)return cs_diag_add(&d->h,"HY001",0,"Memory allocation error");rc=cs_copy_utf16(output,capacity,&n,u,&d->h);if(output_len)*output_len=(SQLINTEGER)n;free(u);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLNativeSqlW(SQLHDBC connection,SQLWCHAR *input,SQLINTEGER input_len,SQLWCHAR *output,SQLINTEGER capacity,SQLINTEGER *output_len) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLNativeSqlW(connection, input, input_len, output, capacity, output_len);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLSetCursorName(SQLHSTMT statement,SQLCHAR *name,SQLSMALLINT length){cs_stmt*s=(cs_stmt*)statement;size_t n;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);if(!name)return cs_diag_add(&s->h,"HY009",0,"Cursor name is null");n=cs_input_len(name,length);if(n>=sizeof(s->cursor_name))return cs_diag_add(&s->h,"HY090",0,"Cursor name is too long");memcpy(s->cursor_name,name,n);s->cursor_name[n]=0;return SQL_SUCCESS;}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetCursorName(SQLHSTMT statement,SQLCHAR *name,SQLSMALLINT length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetCursorName(statement, name, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLGetCursorName(SQLHSTMT statement,SQLCHAR *name,SQLSMALLINT capacity,SQLSMALLINT *length){cs_stmt*s=(cs_stmt*)statement;SQLLEN n=0;SQLRETURN rc;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);if(!s->cursor_name[0])snprintf(s->cursor_name,sizeof(s->cursor_name),"SQL_CUR_%p",(void*)s);rc=cs_copy_utf8(name,capacity,&n,s->cursor_name,&s->h);if(length)*length=(SQLSMALLINT)n;return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetCursorName(SQLHSTMT statement,SQLCHAR *name,SQLSMALLINT capacity,SQLSMALLINT *length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetCursorName(statement, name, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLBulkOperations(SQLHSTMT statement,SQLSMALLINT op){cs_stmt*s=(cs_stmt*)statement;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);return cs_diag_add(&s->h,"HYC00",0,"Bulk operation %d is not implemented",op);}

CSODBC_EXPORT SQLRETURN SQL_API SQLBulkOperations(SQLHSTMT statement,SQLSMALLINT op) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLBulkOperations(statement, op);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLSetPos(SQLHSTMT statement,SQLSETPOSIROW row,SQLUSMALLINT op,SQLUSMALLINT lock){cs_stmt*s=(cs_stmt*)statement;(void)row;(void)op;(void)lock;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);return cs_diag_add(&s->h,"HYC00",0,"Positioned updates are not implemented");}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetPos(SQLHSTMT statement,SQLSETPOSIROW row,SQLUSMALLINT op,SQLUSMALLINT lock) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetPos(statement, row, op, lock);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLParamOptions(SQLHSTMT statement,SQLULEN rows,SQLULEN *processed){cs_stmt*s=(cs_stmt*)statement;if(!cs_valid_handle(statement,SQL_HANDLE_STMT))return SQL_INVALID_HANDLE;cs_diag_clear(&s->h);if(rows!=1)return cs_diag_add(&s->h,"HYC00",0,"Parameter arrays are not implemented");s->params_processed=processed;return SQL_SUCCESS;}

CSODBC_EXPORT SQLRETURN SQL_API SQLParamOptions(SQLHSTMT statement,SQLULEN rows,SQLULEN *processed) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLParamOptions(statement, rows, processed);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetDiagFieldW(SQLSMALLINT type,SQLHANDLE handle,
    SQLSMALLINT record,SQLSMALLINT id,SQLPOINTER info,SQLSMALLINT capacity,SQLSMALLINT *length){
    char temp[1024]={0};SQLSMALLINT n=0;SQLLEN wn=0;SQLRETURN rc;
    if(id!=SQL_DIAG_SQLSTATE&&id!=SQL_DIAG_MESSAGE_TEXT&&id!=SQL_DIAG_CLASS_ORIGIN&&id!=SQL_DIAG_SUBCLASS_ORIGIN&&id!=SQL_DIAG_CONNECTION_NAME&&id!=SQL_DIAG_SERVER_NAME)
        return SQLGetDiagField(type,handle,record,id,info,capacity,length);
    rc=SQLGetDiagField(type,handle,record,id,temp,sizeof(temp),&n);if(!SQL_SUCCEEDED(rc))return rc;
    rc=cs_copy_utf16((SQLWCHAR *)info,capacity/sizeof(SQLWCHAR),&wn,temp,NULL);if(length)*length=(SQLSMALLINT)(wn*sizeof(SQLWCHAR));return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetDiagFieldW(SQLSMALLINT type,SQLHANDLE handle,
    SQLSMALLINT record,SQLSMALLINT id,SQLPOINTER info,SQLSMALLINT capacity,SQLSMALLINT *length) {
    cs_mutex *cs__m = cs_handle_lock(type, handle);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetDiagFieldW(type, handle, record, id, info, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

/* Come SQLError: percorre i record uno per chiamata, non ripete il primo. */
CSODBC_EXPORT SQLRETURN SQL_API SQLErrorW(SQLHENV env,SQLHDBC dbc,SQLHSTMT stmt,
    SQLWCHAR *state,SQLINTEGER *native,SQLWCHAR *message,SQLSMALLINT capacity,SQLSMALLINT *length){
    SQLSMALLINT type=0;SQLHANDLE handle=NULL;
    SQLSMALLINT record=cs_diag_take_next(env,dbc,stmt,&type,&handle);
    if(record<0)return SQL_INVALID_HANDLE;
    if(record==0)return SQL_NO_DATA;
    return SQLGetDiagRecW(type,handle,record,state,native,message,capacity,length);
}

static SQLRETURN SQL_API cs_i_SQLBrowseConnectW(SQLHDBC connection,SQLWCHAR *input,
    SQLSMALLINT input_len,SQLWCHAR *output,SQLSMALLINT output_cap,SQLSMALLINT *output_len){
    char *u=cs_utf16_to_utf8(input,input_len),temp[2048];SQLSMALLINT n=0;SQLLEN wn=0;SQLRETURN rc,copy;
    if(!u)return SQL_ERROR;rc=SQLBrowseConnect(connection,(SQLCHAR *)u,SQL_NTS,(SQLCHAR *)temp,sizeof(temp),&n);free(u);
    if(rc!=SQL_NEED_DATA&&!SQL_SUCCEEDED(rc))return rc;copy=cs_copy_utf16(output,output_cap,&wn,temp,NULL);if(output_len)*output_len=(SQLSMALLINT)wn;return copy==SQL_SUCCESS?rc:copy;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLBrowseConnectW(SQLHDBC connection,SQLWCHAR *input,
    SQLSMALLINT input_len,SQLWCHAR *output,SQLSMALLINT output_cap,SQLSMALLINT *output_len) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, connection);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLBrowseConnectW(connection, input, input_len, output, output_cap, output_len);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLGetTypeInfoW(SQLHSTMT statement,SQLSMALLINT type){return SQLGetTypeInfo(statement,type);}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetTypeInfoW(SQLHSTMT statement,SQLSMALLINT type) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetTypeInfoW(statement, type);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLSetCursorNameW(SQLHSTMT statement,SQLWCHAR *name,SQLSMALLINT length){char*u=cs_utf16_to_utf8(name,length);SQLRETURN rc;if(!u)return SQL_ERROR;rc=SQLSetCursorName(statement,(SQLCHAR *)u,SQL_NTS);free(u);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetCursorNameW(SQLHSTMT statement,SQLWCHAR *name,SQLSMALLINT length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetCursorNameW(statement, name, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLGetCursorNameW(SQLHSTMT statement,SQLWCHAR *name,SQLSMALLINT capacity,SQLSMALLINT *length){char temp[256];SQLSMALLINT n=0;SQLLEN wn=0;SQLRETURN rc=SQLGetCursorName(statement,(SQLCHAR *)temp,sizeof(temp),&n);if(!SQL_SUCCEEDED(rc))return rc;rc=cs_copy_utf16(name,capacity,&wn,temp,NULL);if(length)*length=(SQLSMALLINT)wn;return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetCursorNameW(SQLHSTMT statement,SQLWCHAR *name,SQLSMALLINT capacity,SQLSMALLINT *length) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetCursorNameW(statement, name, capacity, length);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static SQLRETURN SQL_API cs_i_SQLColAttributeW(SQLHSTMT statement,SQLUSMALLINT column,
    SQLUSMALLINT field,SQLPOINTER chars,SQLSMALLINT capacity,SQLSMALLINT *char_len,
#ifdef _WIN64
    SQLLEN *numeric
#else
    SQLPOINTER numeric
#endif
){
    char temp[1024]={0};SQLSMALLINT n=0;SQLLEN wn=0;SQLRETURN rc;
    rc=SQLColAttribute(statement,column,field,temp,sizeof(temp),&n,numeric);if(!SQL_SUCCEEDED(rc))return rc;
    if(cs_colattr_is_string(field)){rc=cs_copy_utf16((SQLWCHAR *)chars,capacity/sizeof(SQLWCHAR),&wn,temp,NULL);if(char_len)*char_len=(SQLSMALLINT)(wn*sizeof(SQLWCHAR));}
    return rc;
}

CSODBC_EXPORT SQLRETURN SQL_API SQLColAttributeW(SQLHSTMT statement,SQLUSMALLINT column,
    SQLUSMALLINT field,SQLPOINTER chars,SQLSMALLINT capacity,SQLSMALLINT *char_len,
#ifdef _WIN64
    SQLLEN *numeric
#else
    SQLPOINTER numeric
#endif
) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, statement);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLColAttributeW(statement, column, field, chars, capacity, char_len, numeric);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

static char *cs_wmeta_arg(SQLWCHAR *value,SQLSMALLINT length){return value?cs_utf16_to_utf8(value,length):NULL;}
#define CS_FREE4(a,b,c,d) do{free(a);free(b);free(c);free(d);}while(0)

static SQLRETURN SQL_API cs_i_SQLTablesW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLWCHAR*d,SQLSMALLINT dl){char*aa=cs_wmeta_arg(a,al),*bb=cs_wmeta_arg(b,bl),*cc=cs_wmeta_arg(c,cl),*dd=cs_wmeta_arg(d,dl);SQLRETURN rc=SQLTables(s,(SQLCHAR*)aa,SQL_NTS,(SQLCHAR*)bb,SQL_NTS,(SQLCHAR*)cc,SQL_NTS,(SQLCHAR*)dd,SQL_NTS);CS_FREE4(aa,bb,cc,dd);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLTablesW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLWCHAR*d,SQLSMALLINT dl) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLTablesW(s, a, al, b, bl, c, cl, d, dl);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLColumnsW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLWCHAR*d,SQLSMALLINT dl){char*aa=cs_wmeta_arg(a,al),*bb=cs_wmeta_arg(b,bl),*cc=cs_wmeta_arg(c,cl),*dd=cs_wmeta_arg(d,dl);SQLRETURN rc=SQLColumns(s,(SQLCHAR*)aa,SQL_NTS,(SQLCHAR*)bb,SQL_NTS,(SQLCHAR*)cc,SQL_NTS,(SQLCHAR*)dd,SQL_NTS);CS_FREE4(aa,bb,cc,dd);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLColumnsW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLWCHAR*d,SQLSMALLINT dl) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLColumnsW(s, a, al, b, bl, c, cl, d, dl);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLPrimaryKeysW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl){char*aa=cs_wmeta_arg(a,al),*bb=cs_wmeta_arg(b,bl),*cc=cs_wmeta_arg(c,cl);SQLRETURN rc=SQLPrimaryKeys(s,(SQLCHAR*)aa,SQL_NTS,(SQLCHAR*)bb,SQL_NTS,(SQLCHAR*)cc,SQL_NTS);free(aa);free(bb);free(cc);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLPrimaryKeysW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLPrimaryKeysW(s, a, al, b, bl, c, cl);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLStatisticsW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLUSMALLINT u,SQLUSMALLINT r){char*aa=cs_wmeta_arg(a,al),*bb=cs_wmeta_arg(b,bl),*cc=cs_wmeta_arg(c,cl);SQLRETURN rc=SQLStatistics(s,(SQLCHAR*)aa,SQL_NTS,(SQLCHAR*)bb,SQL_NTS,(SQLCHAR*)cc,SQL_NTS,u,r);free(aa);free(bb);free(cc);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLStatisticsW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLUSMALLINT u,SQLUSMALLINT r) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLStatisticsW(s, a, al, b, bl, c, cl, u, r);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLSpecialColumnsW(SQLHSTMT s,SQLUSMALLINT id,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLUSMALLINT scope,SQLUSMALLINT nul){char*aa=cs_wmeta_arg(a,al),*bb=cs_wmeta_arg(b,bl),*cc=cs_wmeta_arg(c,cl);SQLRETURN rc=SQLSpecialColumns(s,id,(SQLCHAR*)aa,SQL_NTS,(SQLCHAR*)bb,SQL_NTS,(SQLCHAR*)cc,SQL_NTS,scope,nul);free(aa);free(bb);free(cc);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLSpecialColumnsW(SQLHSTMT s,SQLUSMALLINT id,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLUSMALLINT scope,SQLUSMALLINT nul) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSpecialColumnsW(s, id, a, al, b, bl, c, cl, scope, nul);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLForeignKeysW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLWCHAR*d,SQLSMALLINT dl,SQLWCHAR*e,SQLSMALLINT el,SQLWCHAR*f,SQLSMALLINT fl){char*aa=cs_wmeta_arg(a,al),*bb=cs_wmeta_arg(b,bl),*cc=cs_wmeta_arg(c,cl),*dd=cs_wmeta_arg(d,dl),*ee=cs_wmeta_arg(e,el),*ff=cs_wmeta_arg(f,fl);SQLRETURN rc=SQLForeignKeys(s,(SQLCHAR*)aa,SQL_NTS,(SQLCHAR*)bb,SQL_NTS,(SQLCHAR*)cc,SQL_NTS,(SQLCHAR*)dd,SQL_NTS,(SQLCHAR*)ee,SQL_NTS,(SQLCHAR*)ff,SQL_NTS);free(aa);free(bb);free(cc);free(dd);free(ee);free(ff);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLForeignKeysW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLWCHAR*d,SQLSMALLINT dl,SQLWCHAR*e,SQLSMALLINT el,SQLWCHAR*f,SQLSMALLINT fl) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLForeignKeysW(s, a, al, b, bl, c, cl, d, dl, e, el, f, fl);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLProceduresW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl){char*aa=cs_wmeta_arg(a,al),*bb=cs_wmeta_arg(b,bl),*cc=cs_wmeta_arg(c,cl);SQLRETURN rc=SQLProcedures(s,(SQLCHAR*)aa,SQL_NTS,(SQLCHAR*)bb,SQL_NTS,(SQLCHAR*)cc,SQL_NTS);free(aa);free(bb);free(cc);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLProceduresW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLProceduresW(s, a, al, b, bl, c, cl);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLProcedureColumnsW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLWCHAR*d,SQLSMALLINT dl){char*aa=cs_wmeta_arg(a,al),*bb=cs_wmeta_arg(b,bl),*cc=cs_wmeta_arg(c,cl),*dd=cs_wmeta_arg(d,dl);SQLRETURN rc=SQLProcedureColumns(s,(SQLCHAR*)aa,SQL_NTS,(SQLCHAR*)bb,SQL_NTS,(SQLCHAR*)cc,SQL_NTS,(SQLCHAR*)dd,SQL_NTS);CS_FREE4(aa,bb,cc,dd);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLProcedureColumnsW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLWCHAR*d,SQLSMALLINT dl) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLProcedureColumnsW(s, a, al, b, bl, c, cl, d, dl);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLColumnPrivilegesW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLWCHAR*d,SQLSMALLINT dl){char*aa=cs_wmeta_arg(a,al),*bb=cs_wmeta_arg(b,bl),*cc=cs_wmeta_arg(c,cl),*dd=cs_wmeta_arg(d,dl);SQLRETURN rc=SQLColumnPrivileges(s,(SQLCHAR*)aa,SQL_NTS,(SQLCHAR*)bb,SQL_NTS,(SQLCHAR*)cc,SQL_NTS,(SQLCHAR*)dd,SQL_NTS);CS_FREE4(aa,bb,cc,dd);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLColumnPrivilegesW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl,SQLWCHAR*d,SQLSMALLINT dl) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLColumnPrivilegesW(s, a, al, b, bl, c, cl, d, dl);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLTablePrivilegesW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl){char*aa=cs_wmeta_arg(a,al),*bb=cs_wmeta_arg(b,bl),*cc=cs_wmeta_arg(c,cl);SQLRETURN rc=SQLTablePrivileges(s,(SQLCHAR*)aa,SQL_NTS,(SQLCHAR*)bb,SQL_NTS,(SQLCHAR*)cc,SQL_NTS);free(aa);free(bb);free(cc);return rc;}

CSODBC_EXPORT SQLRETURN SQL_API SQLTablePrivilegesW(SQLHSTMT s,SQLWCHAR*a,SQLSMALLINT al,SQLWCHAR*b,SQLSMALLINT bl,SQLWCHAR*c,SQLSMALLINT cl) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLTablePrivilegesW(s, a, al, b, bl, c, cl);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
#undef CS_FREE4

static SQLRETURN SQL_API cs_i_SQLGetConnectAttrA(SQLHDBC c,SQLINTEGER a,SQLPOINTER v,SQLINTEGER n,SQLINTEGER*l){return SQLGetConnectAttr(c,a,v,n,l);}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetConnectAttrA(SQLHDBC c,SQLINTEGER a,SQLPOINTER v,SQLINTEGER n,SQLINTEGER*l) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, c);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetConnectAttrA(c, a, v, n, l);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLSetConnectAttrA(SQLHDBC c,SQLINTEGER a,SQLPOINTER v,SQLINTEGER n){return SQLSetConnectAttr(c,a,v,n);}

CSODBC_EXPORT SQLRETURN SQL_API SQLSetConnectAttrA(SQLHDBC c,SQLINTEGER a,SQLPOINTER v,SQLINTEGER n) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, c);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLSetConnectAttrA(c, a, v, n);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLGetStmtAttrA(SQLHSTMT s,SQLINTEGER a,SQLPOINTER v,SQLINTEGER n,SQLINTEGER*l){return SQLGetStmtAttr(s,a,v,n,l);}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetStmtAttrA(SQLHSTMT s,SQLINTEGER a,SQLPOINTER v,SQLINTEGER n,SQLINTEGER*l) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_STMT, s);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetStmtAttrA(s, a, v, n, l);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLGetInfoA(SQLHDBC c,SQLUSMALLINT t,SQLPOINTER v,SQLSMALLINT n,SQLSMALLINT*l){return SQLGetInfo(c,t,v,n,l);}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetInfoA(SQLHDBC c,SQLUSMALLINT t,SQLPOINTER v,SQLSMALLINT n,SQLSMALLINT*l) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, c);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetInfoA(c, t, v, n, l);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLGetDiagRecA(SQLSMALLINT t,SQLHANDLE h,SQLSMALLINT r,SQLCHAR*s,SQLINTEGER*n,SQLCHAR*m,SQLSMALLINT c,SQLSMALLINT*l){return SQLGetDiagRec(t,h,r,s,n,m,c,l);}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetDiagRecA(SQLSMALLINT t,SQLHANDLE h,SQLSMALLINT r,SQLCHAR*s,SQLINTEGER*n,SQLCHAR*m,SQLSMALLINT c,SQLSMALLINT*l) {
    cs_mutex *cs__m = cs_handle_lock(t, h);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetDiagRecA(t, h, r, s, n, m, c, l);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLGetDiagFieldA(SQLSMALLINT t,SQLHANDLE h,SQLSMALLINT r,SQLSMALLINT i,SQLPOINTER v,SQLSMALLINT c,SQLSMALLINT*l){return SQLGetDiagField(t,h,r,i,v,c,l);}

CSODBC_EXPORT SQLRETURN SQL_API SQLGetDiagFieldA(SQLSMALLINT t,SQLHANDLE h,SQLSMALLINT r,SQLSMALLINT i,SQLPOINTER v,SQLSMALLINT c,SQLSMALLINT*l) {
    cs_mutex *cs__m = cs_handle_lock(t, h);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLGetDiagFieldA(t, h, r, i, v, c, l);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}
static SQLRETURN SQL_API cs_i_SQLNativeSqlA(SQLHDBC c,SQLCHAR*i,SQLINTEGER il,SQLCHAR*o,SQLINTEGER oc,SQLINTEGER*ol){return SQLNativeSql(c,i,il,o,oc,ol);}

CSODBC_EXPORT SQLRETURN SQL_API SQLNativeSqlA(SQLHDBC c,SQLCHAR*i,SQLINTEGER il,SQLCHAR*o,SQLINTEGER oc,SQLINTEGER*ol) {
    cs_mutex *cs__m = cs_handle_lock(SQL_HANDLE_DBC, c);
    SQLRETURN cs__rc;
    if (cs__m) cs_mutex_lock(cs__m);
    cs__rc = cs_i_SQLNativeSqlA(c, i, il, o, oc, ol);
    if (cs__m) cs_mutex_unlock(cs__m);
    return cs__rc;
}

#ifdef _WIN32
HINSTANCE cs_dll_module;

BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved){
    (void)reserved;
    if(reason==DLL_PROCESS_ATTACH){
        cs_dll_module=instance;
        /* Nothing here needs per-thread notifications. */
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
#endif
