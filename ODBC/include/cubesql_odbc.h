#ifndef CUBESQL_ODBC_INTERNAL_H
#define CUBESQL_ODBC_INTERNAL_H

#define ODBCVER 0x0380
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sql.h>
#include <sqlext.h>
#include <sqlucode.h>
#else
#include "odbc_compat.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include "cubesql.h"

#ifndef _WIN32
#include <pthread.h>
#endif

#ifdef _WIN32
/* Windows exports are declared in windows/cubesqlodbc.def. */
#define CSODBC_EXPORT
#else
#define CSODBC_EXPORT __attribute__((visibility("default")))
#endif

/*
 * The version lives in cubesql_odbc_version.h so that the C sources and the
 * Windows resource compiler cannot drift apart.
 */
#include "cubesql_odbc_version.h"

/*
 * The driver is registered as an ODBC 2.0 driver on purpose: it does not yet
 * implement explicit descriptors, and in 2.0 compatibility mode the Driver
 * Manager maps the ODBC 3.x descriptor calls for us. See the note in README.md.
 */
#define CSODBC_ODBC_VERSION "03.80"
#define CSODBC_DRIVER_ODBC_VERSION "02.00"
#define CSODBC_MAX_DIAG 8
#define CSODBC_MAX_COLS 1024
#define CSODBC_MAX_PARAMS 1024
#define CSODBC_MAGIC 0x43534f44u

/*
 * Per-connection recursive mutex. The Driver Manager does not serialise calls,
 * so every entry point that touches a connection, its statements, or the
 * underlying CubeSQL socket has to serialise on the owning connection.
 */
#ifdef _WIN32
typedef CRITICAL_SECTION cs_mutex;
#else
typedef pthread_mutex_t cs_mutex;
#endif

void cs_mutex_init(cs_mutex *m);
void cs_mutex_destroy(cs_mutex *m);
void cs_mutex_lock(cs_mutex *m);
void cs_mutex_unlock(cs_mutex *m);
/* Non-zero when the lock was acquired. */
int cs_mutex_trylock(cs_mutex *m);

typedef struct cs_diag_record {
    char state[6];
    SQLINTEGER native;
    char message[512];
} cs_diag_record;

typedef struct cs_handle {
    uint32_t magic;
    SQLSMALLINT type;
    SQLRETURN last_return;
    SQLSMALLINT diag_count;
    cs_diag_record diag[CSODBC_MAX_DIAG];
} cs_handle;

typedef struct cs_env cs_env;
typedef struct cs_dbc cs_dbc;
typedef struct cs_stmt cs_stmt;

typedef struct cs_col_binding {
    SQLSMALLINT c_type;
    SQLPOINTER value;
    SQLLEN buffer_length;
    SQLLEN *indicator;
} cs_col_binding;

typedef struct cs_param_binding {
    SQLSMALLINT io_type;
    SQLSMALLINT c_type;
    SQLSMALLINT sql_type;
    SQLULEN column_size;
    SQLSMALLINT scale;
    SQLPOINTER value;
    SQLLEN buffer_length;
    SQLLEN *indicator;
    unsigned char *at_exec;
    SQLLEN at_exec_len;
    SQLLEN at_exec_cap;
} cs_param_binding;

struct cs_env {
    cs_handle h;
    SQLINTEGER odbc_version;
    SQLINTEGER output_nts;
    SQLULEN connection_pooling;
    SQLULEN cp_match;
    cs_dbc *connections;
    cs_mutex lock;
};

struct cs_dbc {
    cs_handle h;
    cs_env *env;
    cs_dbc *next;
    csqldb *db;
    cs_stmt *statements;
    int connected;
    int in_transaction;
    /* Set when SQLCancel had to drop the socket to interrupt a call. */
    int dead;
    /* Non-zero when SQL_C_CHAR uses the ANSI code page rather than raw UTF-8. */
    int ansi_charset;
    SQLULEN autocommit;
    SQLULEN access_mode;
    SQLULEN txn_isolation;
    SQLULEN login_timeout;
    SQLULEN connection_timeout;
    /*
     * Attributes the driver accepts and remembers but that do not change how it
     * talks to CubeSQL. Rejecting them outright breaks common ODBC consumers.
     */
    SQLULEN metadata_id;
    SQLULEN packet_size;
    SQLULEN odbc_cursors;
    SQLULEN async_enable;
    SQLULEN trace;
    SQLULEN translate_option;
    SQLULEN auto_ipd;
    SQLPOINTER quiet_mode;
    char host[256];
    char port[16];
    char user[256];
    char password[256];
    char database[512];
    char dsn[256];
    char encryption[32];
    char dbms_version[32];
    cs_mutex lock;
};

struct cs_stmt {
    cs_handle h;
    cs_dbc *dbc;
    cs_stmt *next;
    csqlc *cursor;
    char *sql;
    SQLLEN row_count;
    SQLLEN current_row;
    SQLLEN getdata_offset[CSODBC_MAX_COLS];
    cs_col_binding columns[CSODBC_MAX_COLS];
    cs_param_binding params[CSODBC_MAX_PARAMS];
    SQLUSMALLINT num_params;
    SQLUSMALLINT at_exec_param;
    int need_data_active;
    SQLULEN max_rows;
    SQLULEN max_length;
    SQLULEN query_timeout;
    SQLULEN row_array_size;
    SQLULEN *rows_fetched;
    SQLUSMALLINT *row_status;
    SQLULEN paramset_size;
    SQLULEN *params_processed;
    SQLUSMALLINT *param_status;
    SQLUSMALLINT *param_operation;
    SQLUSMALLINT *row_operation;
    /* Rowset binding. row_bind_type is SQL_BIND_BY_COLUMN or a struct stride. */
    SQLULEN row_bind_type;
    SQLULEN param_bind_type;
    SQLULEN *row_bind_offset;
    SQLULEN *param_bind_offset;
    SQLULEN rowset_start;
    SQLULEN rowset_count;
    /* Accepted-and-remembered statement attributes. */
    SQLULEN metadata_id;
    SQLULEN noscan;
    SQLULEN async_enable;
    SQLULEN cursor_scrollable;
    SQLULEN cursor_sensitivity;
    SQLULEN keyset_size;
    SQLULEN simulate_cursor;
    SQLULEN cursor_type;
    SQLULEN concurrency;
    SQLULEN retrieve_data;
    SQLULEN use_bookmarks;
    char cursor_name[128];
    int prepared;
    int executed;
};

void cs_diag_clear(cs_handle *h);
SQLRETURN cs_diag_add(cs_handle *h, const char *state, SQLINTEGER native,
                      const char *format, ...);
SQLRETURN cs_diag_warn(cs_handle *h, const char *state, const char *format, ...);
int cs_valid_handle(SQLHANDLE handle, SQLSMALLINT type);
char *cs_utf16_to_utf8(const SQLWCHAR *input, SQLINTEGER length);
SQLRETURN cs_copy_utf8(SQLCHAR *out, SQLLEN capacity, SQLLEN *length,
                       const char *value, cs_handle *diag);
SQLRETURN cs_copy_ansi(SQLCHAR *out, SQLLEN capacity, SQLLEN *length,
                       const char *value, cs_handle *diag, int ansi_charset);
SQLRETURN cs_copy_utf16(SQLWCHAR *out, SQLLEN capacity, SQLLEN *length,
                        const char *value, cs_handle *diag);

/*
 * Connection options shared between the driver and the Windows setup dialog.
 */
/* Bits recording which keys the caller actually supplied. */
#define CS_OPT_SEEN_DSN  0x01u
#define CS_OPT_SEEN_UID  0x02u
#define CS_OPT_SEEN_PWD  0x04u

typedef struct cs_conn_options {
    char dsn[256], host[256], port[16], user[256], password[256];
    char database[512], encryption[32], timeout[16], charset[16];
    unsigned seen;
} cs_conn_options;

char *cs_utf8_to_ansi(const char *utf8, size_t len, size_t *out_len);
char *cs_ansi_to_utf8(const char *ansi, size_t len, size_t *out_len);

int cs_parse_connection_string(cs_conn_options *o, const char *input);
void cs_option_set(char *dst, size_t cap, const char *value);
void cs_conn_apply_defaults(cs_conn_options *o);
int cs_encryption_value(const char *value);

#ifdef _WIN32
/* Set by DllMain so the setup dialogs can locate their own resources. */
extern HINSTANCE cs_dll_module;

/*
 * Implemented in setup.c. Shows the modal connection dialog and returns
 * non-zero when the user confirmed. "connect_mode" drives the layout: the DSN
 * editor shows the DSN name and description fields, the login prompt does not.
 */
int cs_prompt_dialog(HWND parent, cs_conn_options *o, int connect_mode);
#endif

#endif
