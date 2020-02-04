/*
 *  csql.h
 *
 *	This file is the private interface for the CubeSQL Server SDK.
 *	You just need to include the cubesql.h header file in your projects.
 *
 *  (c) 2006-2020 SQLabs srl -- All Rights Reserved
 *  Author: Marco Bambini (MB)
 *
 */

#ifndef __CUBESQL_H__
#define __CUBESQL_H__

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#endif

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>

#ifdef WIN32
#include <Shlwapi.h>
#include <io.h>
#include <float.h>
#include "zlib.h"
#else
#include <zlib.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <netdb.h>
#include <dlfcn.h>
#include <libgen.h>
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

#include "aes.h"
#include "sha1.h"
#include "pseudorandom.h"
	
#ifdef WIN32
// WINDOWS
#define SSL_LIB		        "ssleay32.dll"
#define CRYPTO_LIB	        "libeay32.dll"

#pragma warning (disable: 4005)
#pragma warning (disable: 4068)
#define snprintf		    _snprintf
#define strdup			    _strdup
#define strtoll(x,y,z)	    _strtoi64(x,y,z)
#define BSD_FD_ISSET	    FD_ISSET
#define SHUT_RDWR           2
#define SA SOCKADDR
#define INET_ADDRSTRLEN     16
#define EINTR 			    WSAEINTR
#define EAGAIN 			    WSAEWOULDBLOCK
#define EMSGSIZE 		    WSAEMSGSIZE
#define EAFNOSUPPORT 	    WSAEAFNOSUPPORT
#define EWOULDBLOCK 	    WSAEWOULDBLOCK
#define ECONNRESET 		    WSAECONNRESET
#define EINPROGRESS 	    WSAEINPROGRESS
#define IPV6_V6ONLY		    27
		
#define ioctl               ioctlsocket
#define bsd_h_errno()       h_errno
#define bsd_setsockopt      setsockopt
#define bsd_getsockopt      getsockopt
#define bsd_inet_pton       inet_pton
#define bsd_shutdown        shutdown
#define cleanup()           WSACleanup()
#define bsd_select	        select
#define sock_read(a,b,c)	recv((a), (b), (c), 0L)
#define sock_write(a,b,c)	send((a), (b), (c), 0L)
#define	PATH_SEPARATOR	    "\\"
#define Pause()             Sleep(INFINITE)
#define mssleep(ms)         Sleep(ms)
	
typedef int socklen_t;
typedef int ssize_t;
typedef unsigned long in_addr_t;
	
#else
// UNIX
#ifdef __APPLE__
#define SSL_LIB		                    "libssl.dylib"
#define CRYPTO_LIB                      "libcrypto.dylib"
#else
#define SSL_LIB		                    "libssl.so"
#define CRYPTO_LIB	                    "libcrypto.so"
#endif

#define BSD_FD_ISSET	                FD_ISSET
#define bsd_h_errno()                   h_errno
#define bsd_setsockopt                  setsockopt
#define bsd_getsockopt                  getsockopt
#define bsd_inet_pton                   inet_pton
#define bsd_shutdown                    shutdown
#define bsd_select                      select
#define	PATH_SEPARATOR                  "/"
#define closesocket(s)                  close(s)
#define cleanup()
#define sock_write                      write
#define sock_read                       read
#define Pause()                         pause()
#define mssleep(ms)                     usleep((ms)*1000)
#endif
	
/* PROTOCOL MACROS */
#define SETBIT(x, b)					((x) |= (b))
#define CLEARBIT(x, b)					((x) &= ~(b))
#define TESTBIT(x, b)					(((x) & (b)) != 0)

/* CLIENT -> SERVER */
#define CLIENT_SUPPORT_COMPRESSION		0x01
#define CLIENT_UNUSED_1					0x02
#define CLIENT_UNUSED_2					0x04
#define CLIENT_COMPRESSED_PACKET		0x08
#define CLIENT_ADD_ROWID_COLUMN			0x10
#define CLIENT_PARTIAL_PACKET			0x20
#define CLIENT_REQUEST_SERVER_SIDE		0x40
#define CLIENT_UNUSED_3					0x80

/* SERVER -> CLIENT */
#define SERVER_PROTOCOL_2009			0x01
#define SERVER_UNUSED_1					0x02
#define SERVER_HAS_ROWID_COLUMN			0x04
#define SERVER_COMPRESSED_PACKET		0x08
#define SERVER_UNUSED_2					0x10
#define SERVER_PARTIAL_PACKET			0x20
#define SERVER_SERVER_SIDE				0x40
#define SERVER_HAS_TABLE_NAME			0x80

// client version
#define k2007PROTOCOL					3
#define k2011PROTOCOL					4
	
#define ERR_SOCKET_INVALID_PORT_HOST	800
#define ERR_SOCKET						802
#define ERR_SOCKET_NULL					805
#define ERR_SOCKET_TIMEOUT				810
#define ERR_SOCKET_WRITE				820
#define ERR_SOCKET_READ					830
#define ERR_WRONG_HEADER				835
#define ERR_WRONG_SIGNATURE				840
#define ERR_NULL_BUFFER					845
#define ERR_WRONG_Y						850
#define ERR_NULL_RANDBUFF				855
#define ERR_RANDPOOL					860
#define ERR_DB_IS_NULL					865
#define ERR_BUFFER_NULL					870
#define END_CHUNK						777
#define ERR_SSL							888
	
/* common definitions */
#define BLOCK_LEN						AES_BLOCK_SIZE
#define PROTOCOL_SIGNATURE				'SQLS'
#define kRANDPOOLSIZE					20
#define kHEADER_SIZE					32
#define NULL_VALUE						-1
#define kNUMBUFFER						1000
#define kMAXCHUNK						100*1024
#define NO_TIMEOUT						0
#define CONNECT_TIMEOUT					5
    
#if defined(HAVE_BZERO) || defined(bzero)
// do nothing
#else
#undef  bzero
#define bzero(ptr,n)					memset(ptr, 0, n)
#endif
	
#if defined(HAVE_BCOPY) || defined(bcopy)
// do nothing
#else
#undef  bcopy
#define bcopy(from, to, len)			memcpy ((to), (from), (len))
#endif

#ifndef WIN32
typedef int SOCKET;
#endif

#if !CUBESQL_ENABLE_SSL_ENCRYPTION
#define CUBESQL_STATIC_SSL_LIBRARY      0
#define CUBESQL_EXTERN_SSL_LIBRARY      0
#define CUBESQL_DYNAMIC_SSL_LIBRARY     0
#else
#define CUBESQL_LOG_LOADSSL_ISSUES      0
#endif

#if CUBESQL_STATIC_SSL_LIBRARY
// means that libs are statically linked
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#define X509_CERT_SSL       X509
#define X509_NAME_SSL       X509_NAME
#else
// common part between CUBESQL_EXTERN_SSL_LIBRARY and CUBESQL_DYNAMIC_SSL_LIBRARY
    
// Snatched from OpenSSL includes. I put the prototypes here to be independent
// from the OpenSSL source installation. Having this, mongoose + SSL can be
// built on any system with binary SSL libraries installed.
typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct X509_name_st X509_NAME_SSL;
typedef struct stack_st	STACK;
typedef struct X509_st X509_CERT_SSL;
typedef struct X509_EXTENSION_st X509_EXTENSION;
typedef struct CONF_VALUE_st CONF_VALUE;
typedef struct X509V3_EXT_METHOD_st X509V3_EXT_METHOD;
typedef struct ssl_chipher_st SSL_CIPHER;
typedef struct dh_st DH;

#define NID_commonName						13
#define X509_V_OK							0
#define X509_V_ERR_APPLICATION_VERIFICATION	50
	
#define STACK_OF(type) STACK
#define SSL_ERROR_WANT_READ					2
#define SSL_ERROR_WANT_WRITE				3
#define SSL_FILETYPE_PEM					1
#define CRYPTO_LOCK							1
	
#define SSL_VERIFY_NONE						0x00
#define SSL_VERIFY_PEER						0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT		0x02
#define SSL_VERIFY_CLIENT_ONCE				0x04
	
#define SSL_OP_ALL                          0x80000FFFL
#define SSL_OP_NO_SSLv2                     0x01000000L
#define SSL_OP_NO_SSLv3                     0x02000000L
#define SSL_OP_NO_TLSv1                     0x04000000L
#define SSL_OP_NO_TLSv1_2                   0x08000000L
#define SSL_OP_NO_TLSv1_1                   0x10000000L

#define SSL_ERROR_NONE						0
#define SSL_ERROR_SSL						1
#define SSL_ERROR_WANT_READ					2
#define SSL_ERROR_WANT_WRITE				3
#define SSL_ERROR_WANT_X509_LOOKUP			4
#define SSL_ERROR_SYSCALL					5 /* look at error stack/return value/errno */
#define SSL_ERROR_ZERO_RETURN				6
#define SSL_ERROR_WANT_CONNECT				7
#define SSL_ERROR_WANT_ACCEPT				8
#define SSL_CTRL_OPTIONS                    32

#define SSLEAY_VERSION                      OPENSSL_VERSION
#define SSLEAY_CFLAGS                       OPENSSL_CFLAGS
#define SSLEAY_BUILT_ON                     OPENSSL_BUILT_ON
#define SSLEAY_PLATFORM                     OPENSSL_PLATFORM
#define SSLEAY_DIR                          OPENSSL_DIR
#define OPENSSL_VERSION                     0
#define OPENSSL_CFLAGS                      1
#define OPENSSL_BUILT_ON                    2
#define OPENSSL_PLATFORM                    3
#define OPENSSL_DIR                         4
#define OPENSSL_ENGINES_DIR                 5
#define OPENSSL_VERSION_STRING              6
#define OPENSSL_FULL_VERSION_STRING         7
    
#if CUBESQL_EXTERN_SSL_LIBRARY
extern void SSL_free(SSL *ssl);
extern int SSL_accept(SSL *ssl);
extern int SSL_connect(SSL *ssl);
extern int SSL_read(SSL *ssl, void *buf, int num);
extern int SSL_write(SSL *ssl, const void *buf, int num);
extern int SSL_get_error(const SSL *ssl, int ret);
extern int SSL_set_fd(SSL *ssl, int fd);
extern SSL *SSL_new(SSL_CTX *ctx);
extern SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
extern const SSL_METHOD *SSLv3_client_method(void);
extern int SSL_library_init(void);
extern int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
extern int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
extern void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, int (*callback)(char *, int, int, void *));
extern void SSL_CTX_free(SSL_CTX *ctx);
extern void SSL_load_error_strings(void);
extern int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
    
extern int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
extern int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
extern void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*verify_callback)(int, X509_STORE_CTX *));
extern void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth);
extern int SSL_shutdown(SSL *ssl);
extern STACK_OF(X509_NAME_SSL) *SSL_load_client_CA_file(const char *file);
extern void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME_SSL) *list);
    
extern X509_CERT_SSL *SSL_get_peer_certificate(const SSL *ssl);
extern long SSL_get_verify_result(const SSL *ssl);
extern int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
extern long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
extern void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);
extern const SSL_METHOD *TLSv1_1_client_method(void);
extern const SSL_METHOD *TLSv1_2_client_method(void);
    
extern int CRYPTO_num_locks(void);
extern void CRYPTO_set_locking_callback(int, int, const char *, int);
extern void CRYPTO_set_id_callback(unsigned long (*id_function)(void));
extern unsigned long ERR_get_error(void);
extern char *ERR_error_string(unsigned long e, char *buf);
extern void ERR_print_errors_fp(FILE *fp);
extern void ERR_error_string_n(unsigned long e, char *buf, size_t len);
extern void ERR_free_strings(void);
extern const char *ERR_lib_error_string(unsigned long e);
extern const char *ERR_func_error_string(unsigned long e);
extern const char *ERR_reason_error_string(unsigned long e);
extern void ERR_load_crypto_strings(void);
extern X509_NAME_SSL *X509_get_subject_name(const X509_CERT_SSL *x);
extern int X509_NAME_get_text_by_NID(X509_NAME_SSL *name, int nid, char *buf,int len);
extern void X509_free(X509_CERT_SSL *a);
extern const char *SSLeay_version(int t);
extern unsigned long SSLeay(void);
    
#if CUBESQL_EXTERN_SSL_DISABLE11
#define OpenSSL_version     SSLeay_version
#define OpenSSL_version_num SSLeay
#define TLS_client_method   SSLv3_client_method
#else
extern const SSL_METHOD *TLS_client_method(void);
extern const char *OpenSSL_version(int t);
extern unsigned long OpenSSL_version_num(void);
#endif

#else
#define CRYPTO_NUM_FUNCS                    17
#define SSL_NUM_FUNCS                       51

#define SSL_free (* (void (*)(SSL *)) ssl_func[0])
#define SSL_accept (* (int (*)(SSL *)) ssl_func[1])
#define SSL_connect (* (int (*)(SSL *)) ssl_func[2])
#define SSL_read (* (int (*)(SSL *, void *, int)) ssl_func[3])
#define SSL_write (* (int (*)(SSL *, const void *,int)) ssl_func[4])
#define SSL_get_error (* (int (*)(SSL *, int)) ssl_func[5])
#define SSL_set_fd (* (int (*)(SSL *, SOCKET)) ssl_func[6])
#define SSL_new (* (SSL * (*)(SSL_CTX *)) ssl_func[7])
#define SSL_CTX_new (* (SSL_CTX * (*)(SSL_METHOD *)) ssl_func[8])
#define SSLv3_client_method (* (SSL_METHOD * (*)(void)) ssl_func[9])
#define SSL_library_init (* (int (*)(void)) ssl_func[10])
#define SSL_CTX_use_PrivateKey_file (* (int (*)(SSL_CTX *, const char *, int)) ssl_func[11])
#define SSL_CTX_use_certificate_file (* (int (*)(SSL_CTX *, const char *, int)) ssl_func[12])
#define SSL_CTX_set_default_passwd_cb (* (void (*)(SSL_CTX *, int (*callback)(char *, int, int, void *))) ssl_func[13])
#define SSL_CTX_free (* (void (*)(SSL_CTX *)) ssl_func[14])
#define SSL_load_error_strings (* (void (*)(void)) ssl_func[15])
#define SSL_CTX_use_certificate_chain_file (* (int (*)(SSL_CTX *, const char *)) ssl_func[16])
	
#define SSL_CTX_load_verify_locations (* (int (*)(SSL_CTX *, const char *, const char *)) ssl_func[17])
#define SSL_CTX_set_default_verify_paths (* (int (*)(SSL_CTX *)) ssl_func[18])
#define SSL_CTX_set_verify (* (void (*) (SSL_CTX *, int, int (*callback)(int, X509_STORE_CTX *))) ssl_func[19])
#define SSL_CTX_set_verify_depth (* (void (*) (SSL_CTX *, int)) ssl_func[20])
#define SSL_shutdown (* (int (*)(SSL *)) ssl_func[21])
#define SSL_load_client_CA_file (* (STACK_OF(X509_NAME_SSL) * (*) (const char *)) ssl_func[22])
#define SSL_CTX_set_client_CA_list (* (void (*) (SSL_CTX *, STACK_OF(X509_NAME_SSL) *)) ssl_func[23])
	
#define SSL_get_peer_certificate (* (X509_CERT_SSL* (*)(SSL *)) ssl_func[24])
#define SSL_get_verify_result (* (long (*)(SSL *)) ssl_func[25])
#define SSL_CTX_set_cipher_list (* (int (*)(SSL_CTX *, const char *)) ssl_func[26])
#define SSL_CTX_ctrl (* (long (*)(SSL_CTX *, int, long, void*)) ssl_func[27])
#define SSL_CTX_set_default_passwd_cb_userdata (* (void (*)(SSL_CTX *, void *)) ssl_func[28])
#define TLSv1_1_client_method (* (SSL_METHOD * (*)(void)) ssl_func[29])
#define TLSv1_2_client_method (* (SSL_METHOD * (*)(void)) ssl_func[30])

#define SSLv23_server_method (* (SSL_METHOD * (*)(void)) ssl_func[31])
#define SSL_get_version (* (const char * (*) (SSL *)) ssl_func[32])
#define SSL_get_current_cipher (* (SSL_CIPHER* (*) (SSL *)) ssl_func[33])
#define SSL_CIPHER_get_name (* (const char * (*) (SSL_CIPHER *)) ssl_func[34])
#define SSL_CIPHER_get_version (* (char * (*) (SSL_CIPHER *)) ssl_func[35])
#define SSL_CIPHER_get_bits (* (int (*) (SSL_CIPHER *, int *)) ssl_func[36])
#define TLS_server_method (* (SSL_METHOD * (*)(void)) ssl_func[47])
#define TLS_client_method (* (SSL_METHOD * (*)(void)) ssl_func[48])

#define DH_new (* (DH * (*)(void)) settings.ssl_func[37])
#define DH_generate_parameters_ex (* (int (*) (DH *, int, int, void *)) ssl_func[38])
#define DH_check (* (int (*) (DH *, int *)) ssl_func[39])
#define DH_generate_key (* (int (*) (DH *)) ssl_func[40])
#define RAND_seed (* (void (*) (const void *, int)) ssl_func[41])
    
#define TLSv1_1_server_method (* (SSL_METHOD * (*)(void)) ssl_func[42])
#define TLSv1_2_server_method (* (SSL_METHOD * (*)(void)) ssl_func[43])
#define SSL_CTX_set_info_callback (* (void (*)(SSL_CTX *, void (*callback)(SSL *, int, int))) ssl_func[44])
    
#define SSL_set_ex_data (* (void (*)(SSL *, int, void *)) ssl_func[45])
#define SSL_get_ex_data (* (void * (*)(SSL *, int)) ssl_func[46])

#define SSL_set_app_data(s,arg) (SSL_set_ex_data(s,0,arg))
#define SSL_get_app_data(s) (SSL_get_ex_data(s,0))
    
#define CRYPTO_num_locks (* (int (*)(void)) crypto_func[0])
#define CRYPTO_set_locking_callback (* (void (*)(void (*)(int, int, const char *, int))) crypto_func[1])
#define CRYPTO_set_id_callback (* (void (*)(unsigned long (*)(void))) crypto_func[2])
#define ERR_get_error (* (unsigned long (*)(void)) crypto_func[3])
#define ERR_error_string (* (char * (*)(unsigned long,char *)) crypto_func[4])
#define ERR_print_errors_fp (* (void (*)(FILE *)) crypto_func[5])
#define ERR_error_string_n (* (void (*) (unsigned long, char*, size_t)) crypto_func[6])
#define ERR_free_strings (* (void (*)(void)) crypto_func[7])
#define ERR_lib_error_string (* (const char * (*) (unsigned long)) crypto_func[8])
#define ERR_func_error_string (* (const char * (*) (unsigned long)) crypto_func[9])
#define ERR_reason_error_string (* (const char * (*) (unsigned long)) crypto_func[10])
#define ERR_load_crypto_strings (* (void (*)(void)) crypto_func[11])
#define X509_get_subject_name (* (X509_NAME_SSL* (*)(X509_CERT_SSL*)) crypto_func[12])
#define X509_NAME_get_text_by_NID (* (int (*)(X509_NAME_SSL*, int, char*, int)) crypto_func[13])
#define X509_free (* (void (*)(X509_CERT_SSL*)) crypto_func[14])
    
#define SSLeay_version (* (const char * (*)(int)) crypto_func[15])
#define SSLeay (* (unsigned long (*)(void)) crypto_func[16])
#define OpenSSL_version (* (const char * (*)(int)) ssl_func[49])
#define OpenSSL_version_num (* (unsigned long (*)(void)) ssl_func[50])
#endif
#endif
    
/* COMMANDS */
#define	kCOMMAND_CONNECT				1
#define	kCOMMAND_SELECT					2
#define kCOMMAND_EXECUTE				3
#define	kCOMMAND_CLOSE					7
#define kCOMMAND_PING					8
#define kCOMMAND_CHUNK					9
#define kCOMMAND_ENDCHUNK				10
#define kCOMMAND_CURSOR_STEP			11
#define kCOMMAND_CURSOR_CLOSE			12
#define kCOMMAND_CHUNK_BIND				19
#define kCOMMAND_IGNORE					666
#define kCOMMAND_ABORT					667
	
/* FIELD VALUES */
#define	kEMPTY_FIELD					0
#define	kNONE							0
#define kZLIB							1
	
/* SELECTORS */
#define kNO_SELECTOR					0
#define kCLEAR_CONNECT_PHASE1			20
#define kCLEAR_CONNECT_PHASE2			21
#define kENCRYPT_CONNECT_PHASE1			22
#define kENCRYPT_CONNECT_PHASE2			23
#define kENCRYPT_CONNECT_PHASE3			24
#define kCHUNK_OK						25
#define kCHUNK_ABORT					26
#define kBIND_START						0
#define kBIND_STEP						27
#define kBIND_FINALIZE					28
#define kBIND_ABORT						29
#define kCLEAR_TOKEN_CONNECT1			40
#define kCLEAR_TOKEN_CONNECT2			41
#define kENCRYPT_TOKEN_CONNECT1			42
#define kENCRYPT_TOKEN_CONNECT2			43	

/* VM PREPARED */
#define kVM_PREPARE						50
#define kVM_BIND						51
#define kVM_EXECUTE						52
#define kVM_SELECT						53
#define kVM_CLOSE						54

#define kDEFAULT_ALLOC_ROWS				100
	
// client -> server header
typedef struct {
	unsigned int	signature;					// PROTOCOL_SIGNATURE defined as 'SQLS'
	unsigned int	packetSize;					// size of the entire packet (header excluded)
	unsigned char	command;					// main command
	unsigned char	selector;					// sub command selector
	unsigned char	flag1;						// bit field
	unsigned char	flag2;						// bit field
	unsigned char	flag3;						// bit field
	unsigned char	encryptedPacket;			// kEmptyField, ENCRYPTION_NONE, AES128, AES192, AES256
	unsigned char	protocolVersion;			// always 3 in 2007, 4 in 2011
	unsigned char	clientType;					// always 3 in 2007 and 2008
	unsigned int	numFields;					// number of fields in the command (I could use 2 bytes instead of 4)
	unsigned int	expandedSize;				// if packet is compressed, this is the expanded size of the packet
	unsigned int	timeout;					// timeout value
	unsigned short	reserved1;					// unused in this version
	unsigned short	reserved2;					// unused in this version
} inhead;

// server -> client header
typedef struct {
	unsigned int	signature;					// PROTOCOL_SIGNATURE defined as 'SQLS'
	unsigned int	packetSize;					// size of the entire packet (header excluded)
	unsigned short	errorCode;					// 0 means no error
	unsigned char	flag1;						// bit field
	unsigned char	encryptedPacket;			// kEmptyField, ENCRYPTION_NONE, AES128, AES192, AES256
	unsigned int	expandedSize;				// if flag1 is COMPRESSED_PACKET this is the expanded size of the entire buffer
	unsigned int	rows;						// number of rows in the cursor
	unsigned int	cols;						// number of columns in the cursor (it could be 2 bytes instead of 4?)
	unsigned int	numFields;					// number of fields in the command (I could use 2 bytes instead of 4)
	unsigned short	reserved1;					// unused in this version
	unsigned short	reserved2;					// unused in this version
} outhead;
	
struct csqldb {
	int				        timeout;					// timeout used in the socket I/O operations
	int			 	        sockfd;						// the socket
	int				        port;						// port used for the connection
	char			        host[512];					// hostname
	char			        username[512];				// username
	char			        password[512];				// password
	char			        errmsg[512];				// last error message
	int				        errcode;					// last error code
	int				        useOldProtocol;				// flag to set if you want to use the old REALSQLServer protocol
	int				        verifyPeer;					// flag to check if peer verification must be performed
	
	char			        *token;						// optional token used in token connect
	char			        *hostverification;			// optional host verification name to use in SSL peer verification
	void			        *userptr;					// optional pointer saved by the user
	int				        encryption;					// CUBESQL_ENCRYPTION_NONE - CUBESQL_ENCRYPTION_AES128
                                                        // CUBESQL_ENCRYPTION_AES192 - CUBESQL_ENCRYPTION_AES256
    
	csql_aes_encrypt_ctx    encryptkey[1];              // session key used to encrypt data
	csql_aes_decrypt_ctx    decryptkey[1];              // session key used to decrypt data

	int				        toread;
	char			        *inbuffer;
	int				        insize;
	
	inhead			        request;                    // request header
	outhead			        reply;                      // response header
	
	SSL_CTX			        *ssl_ctx;
	SSL				        *ssl;
	
	void (*trace) (const char*, void*);                 // trace callback
	void                    *data;                      // user argument to be passed to the callbacks function
};

struct csqlvm {
	csqldb		*db;
	int			vmindex;
};
	
struct csqlc {
	csqldb		*db;
	int			ncols;
	int			nrows;
	int			server_side;
	int			has_rowid;
	int			eof;
	
	char		*data;
	char		*names;
	char		*tables;
	int			*types;
	int			*size;
	
	// reserved
	short		cursor_id;
	int			current_row;
	int			current_buffer;
	int			data_seek;
	int			index;
	
	char		*p0;
	char		*data0;
	int			*size0;
	
	char		*p;
	int			*psum;
	char		**buffer;
	int			**rowsum;
	int			*rowcount;
	int			nbuffer;
	int			nalloc;
};

// private functions
void	csql_libinit (void);
csqldb *csql_dbinit (const char *host, int port, const char *username, const char *password, int timeout, int encryption, const char *ssl_certificate, const char *root_certificate, const char *ssl_certificate_password, const char *ssl_chiper_list);
int		csql_socketinit (csqldb *db);
void	csql_dbfree (csqldb *db);
void	csql_socketclose (csqldb *db);	
int		csql_connect (csqldb *db, int encryption);
int		csql_connect_encrypted (csqldb *db);
int		csql_netread (csqldb *db, int expected_size, int expected_nfields, int is_chunk, int *end_chunk, int timeout);
csqlc  *csql_read_cursor (csqldb *db, csqlc *existing_c);
int		csql_checkinbuffer (csqldb *db);
int		csql_netwrite (csqldb *db, char *size_array, int nsize_array, char *buffer, int nbuffer);
int		csql_ack(csqldb *db, int chunk_code);
int		csql_socketwrite (csqldb *db, const char *buffer, int nbuffer);
int		csql_socketread (csqldb *db, int is_header, int timeout);
int		csql_socketerror (int fd);
int		csql_checkheader(csqldb *db, int expected_size, int expected_nfields, int *end_chunk);
int		csql_sendchunk (csqldb *db, char *buffer, int bufferlen, int buffertype, int is_bind);
char	*csql_receivechunk (csqldb *db, int *len, int *is_end_chunk);
void	csql_initrequest (csqldb *db, int packetsize, int nfields, char command, char selector);
void	random_hash_field (unsigned char hval[], const char *randpoll, const char *field);
void	csql_seterror(csqldb *db, int errcode, const char *errmsg);
int		csql_send_statement (csqldb *db, int command_type, const char *sql, int is_partial, int server_side);	
void	hash_field (unsigned char hval[], const char *field, int len, int times);
void	hex_hash_field (char result[], const char *field, int len);
void	hex_hash_field2 (char result[], const char *field, unsigned char *randpoll);
int		encrypt_buffer (char *buffer, int dim, char random[], csql_aes_encrypt_ctx ctx[1]);
int		decrypt_buffer (char *buffer, int dim, csql_aes_decrypt_ctx ctx[1]);
int		generate_session_key (csqldb *db, int encryption, char *password, char *rand1, char *rand2);
int		csql_bindexecute(csqldb *db, const char *sql, char **colvalue, int *colsize, int *coltype, int ncols);
int		csql_bind_value (csqldb *db, int index, int bindtype, char *value, int len);
csqlc	*csql_cursor_alloc (csqldb *db);
int		csql_cursor_reallocate (csqlc *c);
int		csql_cursor_close (csqlc *c);
int		csql_cursor_step (csqlc *c);
void	csql_load_ssl (void);
const	char *ssl_error(void);
int		encryption_is_ssl (int encryption);
int		ssl_post_connection_check (csqldb *db);
int		ssl_verify_callback (int ok, X509_STORE_CTX *store);
int		ssl_password_callback(char *buf, int size, int flag, void *userdata);
int		wildcmp(const char *wild, const char *string);
	
#if defined(__cplusplus)
}
#endif

#endif
