#ifndef _PSEUDORANDOM_H_
#define _PSEUDORANDOM_H_


#ifdef __cplusplus
    extern "C" {
#endif

#include <time.h>
#include <string.h>

void csql_rand_init (unsigned int seed);
void csql_static_randinit (void);
unsigned int csql_rand_get (void);
void csql_rand_fill (char *buf);
void csql_rand_fill_16 (char *buf);

#ifdef __cplusplus
    }
#endif

#endif

