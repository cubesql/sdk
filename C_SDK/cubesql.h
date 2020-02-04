/*
 *  cubesql.h
 *
 *	This file is the public interface for the cubeSQL Server SDK.
 *	You just need to include this header file in your projects.
 *
 *  (c) 2006-2020 SQLabs srl -- All Rights Reserved
 *  Author: Marco Bambini (MB)
 *
 */

#ifndef CUBESQLSDK_H
#define CUBESQLSDK_H

#ifdef __cplusplus
extern "C" {
#endif
    
#ifdef WIN32
    #ifdef CUBESQL_EXPORTSDLL
    #define CUBESQL_APIEXPORT               __declspec(dllexport)
    #else
    #define CUBESQL_APIEXPORT               __declspec(dllimport)
    #endif
#else
#define CUBESQL_APIEXPORT
#endif
    
#define CUBESQL_SDK_VERSION                 "050804"   // means 5.8.4
    
// custom boolean values (C89 doesn't have boolean support)
#ifndef kTRUE
#define kTRUE                               1
#endif

#ifndef kFALSE
#define kFALSE                              0
#endif
	
// default values
#define	CUBESQL_DEFAULT_PORT                4430
#define CUBESQL_DEFAULT_TIMEOUT             12
    
// client side error codes
#define CUBESQL_NOERR                       0
#define CUBESQL_ERR                         -1
#define CUBESQL_MEMORY_ERROR                -2
#define CUBESQL_PARAMETER_ERROR             -3
#define CUBESQL_PROTOCOL_ERROR              -4
#define CUBESQL_ZLIB_ERROR                  -5
#define CUBESQL_SSL_ERROR                   -6
#define CUBESQL_SSL_CERT_ERROR              -7
#define CUBESQL_SSL_DISABLED_ERROR          -8

// encryption flags used in cubesql_connect
#define CUBESQL_ENCRYPTION_NONE             0
#define CUBESQL_ENCRYPTION_AES128           2
#define CUBESQL_ENCRYPTION_AES192           3
#define CUBESQL_ENCRYPTION_AES256           4
#define CUBESQL_ENCRYPTION_SSL              8
#define CUBESQL_ENCRYPTION_SSL_AES128       CUBESQL_ENCRYPTION_SSL+CUBESQL_ENCRYPTION_AES128
#define CUBESQL_ENCRYPTION_SSL_AES192       CUBESQL_ENCRYPTION_SSL+CUBESQL_ENCRYPTION_AES192
#define CUBESQL_ENCRYPTION_SSL_AES256       CUBESQL_ENCRYPTION_SSL+CUBESQL_ENCRYPTION_AES256
	
// flag used in cubesql_cursor_getfield
#define	CUBESQL_COLNAME                     0
#define CUBESQL_CURROW                      -1
#define	CUBESQL_COLTABLE                    -2
#define CUBESQL_ROWID                       -666
	
// flag used in cubesql_cursor_seek
#define CUBESQL_SEEKNEXT                    -2
#define CUBESQL_SEEKFIRST                   -3
#define CUBESQL_SEEKLAST                    -4
#define CUBESQL_SEEKPREV                    -5

// SSL dynamic libraries custom path
#define CUBESQL_SSL_LIBRARY_PATH            1
#define CUBESQL_CRYPTO_LIBRARY_PATH         2
	
#ifndef int64
#ifdef WIN32
typedef __int64 int64;
#else
typedef long long int int64;
#endif
#endif
	
// column types coming from the server
enum {
	CUBESQL_Type_None		= 0,
	CUBESQL_Type_Integer	= 1,
	CUBESQL_Type_Float		= 2,
	CUBESQL_Type_Text		= 3,
	CUBESQL_Type_Blob		= 4,
	CUBESQL_Type_Boolean	= 5,
	CUBESQL_Type_Date		= 6,
	CUBESQL_Type_Time		= 7,
	CUBESQL_Type_Timestamp	= 8,
	CUBESQL_Type_Currency	= 9
};

// column types to specify in the cubesql_bind command (coltype)
#define CUBESQL_BIND_INTEGER                1
#define CUBESQL_BIND_DOUBLE                 2
#define CUBESQL_BIND_TEXT                   3
#define CUBESQL_BIND_BLOB                   4
#define CUBESQL_BIND_NULL                   5
#define CUBESQL_BIND_INT64                  8
#define CUBESQL_BIND_ZEROBLOB               9
	
// define opaque datatypes and callbacks
typedef struct csqldb csqldb;
typedef struct csqlc csqlc;
typedef struct csqlvm csqlvm;
typedef void (*cubesql_trace_callback) (const char *, void *);
	
// function prototypes
CUBESQL_APIEXPORT const char *cubesql_version (void);
    
CUBESQL_APIEXPORT int		cubesql_connect (csqldb **db, const char *host, int port, const char *username, const char *password, int timeout, int encryption);
CUBESQL_APIEXPORT int		cubesql_connect_ssl (csqldb **db, const char *host, int port, const char *username, const char *password, int timeout, const char *ssl_certificate_path);
CUBESQL_APIEXPORT void		cubesql_disconnect (csqldb *db, int gracefully);
CUBESQL_APIEXPORT int		cubesql_execute (csqldb *db, const char *sql);
CUBESQL_APIEXPORT csqlc		*cubesql_select (csqldb *db, const char *sql, int unused);
CUBESQL_APIEXPORT int		cubesql_commit (csqldb *db);
CUBESQL_APIEXPORT int		cubesql_rollback (csqldb *db);
CUBESQL_APIEXPORT int		cubesql_bind (csqldb *db, const char *sql, char **colvalue, int *colsize, int *coltype, int ncols);
CUBESQL_APIEXPORT int		cubesql_ping (csqldb *db);
CUBESQL_APIEXPORT void		cubesql_cancel (csqldb *db);
CUBESQL_APIEXPORT int		cubesql_errcode (csqldb *db);
CUBESQL_APIEXPORT char		*cubesql_errmsg (csqldb *db);
CUBESQL_APIEXPORT int64		cubesql_changes (csqldb *db);
CUBESQL_APIEXPORT void		cubesql_set_trace_callback (csqldb *db, cubesql_trace_callback trace, void *arg);
CUBESQL_APIEXPORT void      cubesql_setpath (int type, char *path);
    
CUBESQL_APIEXPORT int       cubesql_set_database (csqldb *db, const char *dbname);
CUBESQL_APIEXPORT int64     cubesql_affected_rows (csqldb *db);
CUBESQL_APIEXPORT int64     cubesql_last_inserted_rowID (csqldb *db);
CUBESQL_APIEXPORT void      cubesql_mssleep (int ms);
    
CUBESQL_APIEXPORT int       cubesql_send_data (csqldb *db, const char *buffer, int len);
CUBESQL_APIEXPORT int       cubesql_send_enddata (csqldb *db);
CUBESQL_APIEXPORT char      *cubesql_receive_data (csqldb *db, int *len, int *is_end_chunk);
    
CUBESQL_APIEXPORT csqlvm	*cubesql_vmprepare (csqldb *db, const char *sql);
CUBESQL_APIEXPORT int		cubesql_vmbind_int (csqlvm *vm, int index, int value);
CUBESQL_APIEXPORT int		cubesql_vmbind_double (csqlvm *vm, int index, double value);
CUBESQL_APIEXPORT int		cubesql_vmbind_text (csqlvm *vm, int index, char *value, int len);
CUBESQL_APIEXPORT int		cubesql_vmbind_blob (csqlvm *vm, int index, void *value, int len);
CUBESQL_APIEXPORT int		cubesql_vmbind_null (csqlvm *vm, int index);
CUBESQL_APIEXPORT int		cubesql_vmbind_int64 (csqlvm *vm, int index, int64 value);
CUBESQL_APIEXPORT int		cubesql_vmbind_zeroblob (csqlvm *vm, int index, int len);
CUBESQL_APIEXPORT int		cubesql_vmexecute (csqlvm *vm);
CUBESQL_APIEXPORT csqlc		*cubesql_vmselect (csqlvm *vm);
CUBESQL_APIEXPORT int		cubesql_vmclose (csqlvm *vm);
	
CUBESQL_APIEXPORT int		cubesql_cursor_numrows (csqlc *c);
CUBESQL_APIEXPORT int		cubesql_cursor_numcolumns (csqlc *c);
CUBESQL_APIEXPORT int		cubesql_cursor_currentrow (csqlc *c);
CUBESQL_APIEXPORT int		cubesql_cursor_seek (csqlc *c, int index);
CUBESQL_APIEXPORT int		cubesql_cursor_iseof (csqlc *c);
CUBESQL_APIEXPORT int		cubesql_cursor_columntype (csqlc *c, int index);
CUBESQL_APIEXPORT char		*cubesql_cursor_field (csqlc *c, int row, int column, int *len);
CUBESQL_APIEXPORT int64		cubesql_cursor_rowid (csqlc *c, int row);
CUBESQL_APIEXPORT int64		cubesql_cursor_int64 (csqlc *c, int row, int column, int64 default_value);
CUBESQL_APIEXPORT int		cubesql_cursor_int (csqlc *c, int row, int column, int default_value);
CUBESQL_APIEXPORT double	cubesql_cursor_double (csqlc *c, int row, int column, double default_value);
CUBESQL_APIEXPORT char		*cubesql_cursor_cstring (csqlc *c, int row, int column);
CUBESQL_APIEXPORT char		*cubesql_cursor_cstring_static (csqlc *c, int row, int column, char *static_buffer, int bufferlen);	
CUBESQL_APIEXPORT void		cubesql_cursor_free (csqlc *c);

// private functions
int		cubesql_connect_token (csqldb **db, const char *host, int port, const char *username, const char *password,
							   int timeout, int encryption, char *token, int useOldProtocol, const char *ssl_certificate,
							   const char *root_certificate, const char *ssl_certificate_password, const char *ssl_chiper_list);
int		cubesql_connect_old_protocol (csqldb **db, const char *host, int port, const char *username, const char *password, int timeout, int encryption);
void	cubesql_clear_errors (csqldb *db);
csqldb	*cubesql_cursor_db (csqlc *cursor);
csqlc	*cubesql_cursor_create (csqldb *db, int nrows, int ncolumns, int *types, char **names);
int		cubesql_cursor_addrow (csqlc *cursor, char **row, int *len);
int		cubesql_cursor_columntypebind (csqlc *c, int index);
void	cubesql_setuserptr (csqldb *db, void *userptr);
void	*cubesql_getuserptr (csqldb *db);
void	cubesql_settoken (csqldb *db, char *token);
void	cubesql_sethostverification (csqldb *db, char *hostverification);
char	*cubesql_gettoken (csqldb *db);
void	cubesql_seterror (csqldb *db, int errcode, const char *errmsg);
    
const char *cubesql_sslversion (void);
unsigned long cubesql_sslversion_num (void);
    
#ifdef __cplusplus
}  /* End of the 'extern "C"' block */
#endif

#endif
