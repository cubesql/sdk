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
 * The driver registers as ODBC 3.0.
 *
 * It declared 2.0 for a long time, and that was not free. In 2.0 mode the
 * Driver Manager refuses, on the driver's behalf, everything that arrived with
 * ODBC 3.0 - it never forwards the call. Fourteen InfoTypes came back HY096,
 * SQL_ATTR_METADATA_ID came back HY092, and, the one that made the driver
 * unusable from Excel, SQL_C_SBIGINT came back HYC00, "Driver does not support
 * this parameter". The driver implements that C type and the native tests
 * exercised it, because they call the driver directly; through the Driver
 * Manager it never arrived, so a column reported as SQL_BIGINT - which is what
 * an INTEGER column is - could not be read at all.
 *
 * Two things had to be in place first.
 *
 * The implicit descriptors: a 3.x driver owns four per statement, and they are
 * implemented in driver.c as views onto the binding state cs_stmt already
 * holds, not as a second copy of it.
 *
 * And the Unicode entry points the Driver Manager only looks up in 3.x mode.
 * That second one was the real blocker, and it was mistaken for the first: in
 * 2.0 mode statement attributes are reached through SQLSetStmtOption and
 * SQLGetStmtOption, which this driver exports, so the absence of
 * SQLSetStmtAttrW and SQLGetStmtAttrW was invisible. From 3.0 the Driver
 * Manager looks those up instead, finds nothing, and calls through a null
 * pointer - the "fault inside ODBC32.dll on the first SQLExecDirect" that was
 * blamed on the missing descriptors. Measured: with the descriptors in place
 * and the five missing W entry points still absent, the fault was unchanged.
 *
 * Both spellings of everything are still accepted. A 3.x declaration does not
 * stop consumers sending the 2.x forms, and this driver answers both; see
 * cs_i_SQLColAttribute and cs_i_SQLSetStmtAttr.
 */
#define CSODBC_ODBC_VERSION "03.80"
#define CSODBC_DRIVER_ODBC_VERSION "03.00"
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
    /*
     * How many records SQLError has already handed out. SQLError is the ODBC 2.x
     * interface and is defined to walk the diagnostic records one call at a time,
     * ending with SQL_NO_DATA; callers loop on it until that arrives.
     */
    SQLSMALLINT diag_next;
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

/*
 * The four descriptors that every ODBC 3.x statement owns.
 *
 * This driver keeps its binding state directly in cs_stmt, so a descriptor here
 * is not a container of its own: it is a view onto that state, tagged with
 * which of the four roles it plays. There is then one copy of the truth, and
 * SQLBindCol and SQLSetDescField are two ways of writing the same fields -
 * which is precisely what ODBC says they are. The alternative, a parallel set
 * of records kept in step with the bindings, is the classic way descriptors go
 * wrong.
 *
 * They are allocated with the statement and freed with it: SQL_DESC_ALLOC_TYPE
 * is always SQL_DESC_ALLOC_AUTO.
 */
enum {
    CS_DESC_ARD = 1,  /* application row: what SQLBindCol writes */
    CS_DESC_APD,      /* application parameter: what SQLBindParameter writes */
    CS_DESC_IRD,      /* implementation row: result set metadata, read-only */
    CS_DESC_IPD       /* implementation parameter: the SQL side of parameters */
};

typedef struct cs_desc {
    cs_handle h;
    struct cs_stmt *stmt;
    SQLSMALLINT role;
} cs_desc;

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
    /*
     * Column types taken from the catalogue, resolved once per result set.
     *
     * CubeSQL reports the runtime type of a column, and for a REAL column it
     * reports text: the wire protocol carries a single type code per column and
     * there is no declared type in it. Reporting every such column as VARCHAR
     * makes consumers treat numbers as strings, so when the runtime type is text
     * the driver asks the catalogue what the column was declared as.
     * Zero means "no better answer than the runtime type".
     */
    SQLSMALLINT decl_type[CSODBC_MAX_COLS];
    int types_resolved;

    /* Le quattro viste descrittore su questo stesso stato. */
    cs_desc ard, apd, ird, ipd;
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
