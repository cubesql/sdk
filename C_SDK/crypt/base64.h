#ifndef _BASE64_H_
#define _BASE64_H_


#ifdef __cplusplus
    extern "C" {
#endif

#include <ctype.h>

/* Encode Base64 */
void to64frombits(unsigned char *out, const unsigned char *in, int inlen);

/* Decode Base64 */
int from64tobits(char *out, const char *in);

#ifdef __cplusplus
    }
#endif

#endif

