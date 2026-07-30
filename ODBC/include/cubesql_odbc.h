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

#ifdef _WIN32
/* Windows exports are declared in windows/cubesqlodbc.def. */
#define CSODBC_EXPORT
#else
#define CSODBC_EXPORT __attribute__((visibility("default")))
#endif

#define CSODBC_VERSION "01.00.0000"
#define CSODBC_ODBC_VERSION "03.80"
#define CSODBC_MAX_DIAG 8
#define CSODBC_MAX_COLS 1024
#define CSODBC_MAX_PARAMS 1024
#define CSODBC_MAGIC 0x43534f44u

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
    cs_dbc *connections;
};

struct cs_dbc {
    cs_handle h;
    cs_env *env;
    cs_dbc *next;
    csqldb *db;
    cs_stmt *statements;
    int connected;
    SQLULEN autocommit;
    SQLULEN access_mode;
    SQLULEN txn_isolation;
    SQLULEN login_timeout;
    SQLULEN connection_timeout;
    char host[256];
    char port[16];
    char user[256];
    char password[256];
    char database[512];
    char dsn[256];
    char encryption[32];
    char dbms_version[32];
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
    char cursor_name[128];
    int prepared;
    int executed;
};

void cs_diag_clear(cs_handle *h);
SQLRETURN cs_diag_add(cs_handle *h, const char *state, SQLINTEGER native,
                      const char *format, ...);
int cs_valid_handle(SQLHANDLE handle, SQLSMALLINT type);
char *cs_utf16_to_utf8(const SQLWCHAR *input, SQLINTEGER length);
SQLRETURN cs_copy_utf8(SQLCHAR *out, SQLLEN capacity, SQLLEN *length,
                       const char *value, cs_handle *diag);
SQLRETURN cs_copy_utf16(SQLWCHAR *out, SQLLEN capacity, SQLLEN *length,
                        const char *value, cs_handle *diag);

#endif
