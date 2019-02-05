#ifndef _PSEUDORANDOM_H_
#define _PSEUDORANDOM_H_


#ifdef __cplusplus
    extern "C" {
#endif

#include <time.h>
#include <string.h>

void rand_init (unsigned int seed);
void static_randinit (void);
unsigned int rand_get (void);
void rand_fill (char *buf);
void rand_fill_16 (char *buf);

#ifdef __cplusplus
    }
#endif

#endif

