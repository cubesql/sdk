/*
 *  csql.h
 *
 *	This file is the private interface for the CubeSQL Server SDK.
 *	You just need to include the cubesql.h header file in your projects.
 *
 *  (c) 2006-2023 SQLabs srl -- All Rights Reserved
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

#ifndef HEADER_TLS_H
#define TLS_WANT_POLLIN     -2
#define TLS_WANT_POLLOUT    -3
struct tls;
struct tls_config;
struct tls *tls_client(void);
struct tls_config *tls_config_new(void);
int tls_init(void);
int tls_configure(struct tls *_ctx, struct tls_config *_config);
int tls_connect_socket(struct tls *_ctx, int _s, const char *_servername);
int tls_close(struct tls *_ctx);
int tls_config_set_ca_file(struct tls_config *_config, const char *_ca_file);
int tls_config_set_cert_file(struct tls_config *_config,const char *_cert_file);
int tls_config_set_key_file(struct tls_config *_config, const char *_key_file);
ssize_t tls_read(struct tls *_ctx, void *_buf, size_t _buflen);
ssize_t tls_write(struct tls *_ctx, const void *_buf, size_t _buflen);
const char *tls_error(struct tls *_ctx);
const char *tls_config_error(struct tls_config *_config);
void tls_free(struct tls *_ctx);
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
    int                     family;
	
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
	
    #ifndef CUBESQL_DISABLE_SSL_ENCRYPTION
    struct tls              *tls_context;               // TLS context connection
    #endif
	
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
int		wildcmp(const char *wild, const char *string);
	
#if defined(__cplusplus)
}
#endif

#endif
