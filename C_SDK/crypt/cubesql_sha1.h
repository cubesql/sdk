/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * FIPS pub 180-1: Secure Hash Algorithm (SHA-1)
 * based on: http://csrc.nist.gov/fips/fip180-1.txt
 * implemented by Jun-ichiro itojun Itoh <itojun@itojun.org>
 */

#ifndef _SHA1_H_
#define _SHA1_H_

#ifdef __GNUC__
#include <sys/types.h>
#endif

#ifdef __MWERKS__
#include <sys/types.h>
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

#ifdef WIN32
typedef unsigned char		u_int8_t;
typedef unsigned int		u_int32_t;
typedef unsigned long long	u_int64_t;	
typedef char*				caddr_t;
#endif

#define SHA1_BIG_ENDIAN		1
#define SHA1_LITTLE_ENDIAN	2

#if defined (__ppc__)
#define SHA1_BYTE_ORDER SHA1_BIG_ENDIAN
#else
#define SHA1_BYTE_ORDER SHA1_LITTLE_ENDIAN
#endif

#define SHA1_DIGEST_SIZE 20
#define	SHA1_RESULTLEN	(160/8)

#if defined(HAVE_BZERO) || defined(bzero)
// do nothing
#else
#define bzero(ptr,n)		 memset(ptr, 0, n)
#endif

#if defined(HAVE_BCOPY) || defined(bcopy)
// do nothing
#else
#define bcopy(from, to, len) memcpy ((to), (from), (len))
#endif

struct csql_sha1_ctxt {
	union {
		u_int8_t	b8[20];
		u_int32_t	b32[5];
	} h;
	union {
		u_int8_t	b8[8];
		u_int64_t	b64[1];
	} c;
	union {
		u_int8_t	b8[64];
		u_int32_t	b32[16];
	} m;
	u_int8_t	count;
};

void csql_sha1_init (struct csql_sha1_ctxt *);
void csql_sha1_pad (struct csql_sha1_ctxt *);
void csql_sha1_loop (struct csql_sha1_ctxt *, const caddr_t, size_t);
void csql_sha1_result (struct csql_sha1_ctxt *, caddr_t);

typedef struct csql_sha1_ctxt SHA1_CTX;
#define CSQL_SHA1Init(x)		    csql_sha1_init((x))
#define CSQL_SHA1Update(x, y, z)	csql_sha1_loop((x), (y), (z))
#define CSQL_SHA1Final(x, y)		csql_sha1_result((y), (x))

void csql_sha1(unsigned char hval[], const unsigned char data[], unsigned int len);

#if defined(__cplusplus)
}
#endif

#endif /*__SHA1_H_*/
