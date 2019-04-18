/***********************************************************************
 From: http://remus.rutgers.edu/~rhoads/Code/tt800.c
 Code by Dr. Glenn Rhoads
 Modified by Marco Bambini
 
 A C-program for TT800 : July 8th 1996 Version
 by M. Matsumoto, email: matumoto@math.keio.ac.jp
 genrand() generate one pseudorandom number with double precision
 which is uniformly distributed on [0,1]-interval
 for each call.  One may choose any initial 25 seeds
 except all zeros.

 See: ACM Transactions on Modelling and Computer Simulation,
 Vol. 4, No. 3, 1994, pages 254-266.
***********************************************************************/

#include "pseudorandom.h"

#define N 25
#define M 7

static unsigned int x[N];         /* the 25 seeds */

void csql_rand_init (unsigned int seed)
{
	int k;

	x[0] = (seed|1) & 0xffffffff;
	for (k=1; k<N; k++)
		x[k] = (69069 * x[k-1]) & 0xffffffff;
}

void csql_static_randinit (void)
{
	csql_rand_init((unsigned int)time(NULL));
}

unsigned int csql_rand_get (void)
{
	unsigned int y;
	static unsigned int mag01[2]={ 0x0, 0x8ebfd028};  /* "magic" vector */
	static int k = 0;
	int kk;

	if (k==N)
	{
		for (kk=0; kk < N-M; kk++)
			x[kk] = x[kk+M] ^ (x[kk] >> 1) ^ mag01[x[kk] & 1];

		for (; kk < N; kk++)
			x[kk] = x[kk+(M-N)] ^ (x[kk] >> 1) ^ mag01[x[kk] & 1];

		k=0;
	}
	
	y = x[k++];
	y ^= (y << 7) & 0x2b5b2500;
	y ^= (y << 15) & 0xdb8b0000;
	y &= 0xffffffff;     /* you may delete this line if word size = 32 */
	y ^= (y >> 16);

	return y;
}

void csql_rand_fill (char *buf)
{	
	unsigned int randint, i, times;
	
	times = 20 / sizeof(unsigned int);
	for (i=0; i<times; i++)
	{
        randint = csql_rand_get();
		memcpy(buf + (i*sizeof(unsigned int)), &randint, sizeof(unsigned int));
	}
}

void csql_rand_fill_16 (char *buf)
{	
	unsigned int randint, i, times;
	
	times = 16 / sizeof(unsigned int);
	for (i=0; i<times; i++)
	{
		randint = csql_rand_get();
		memcpy(buf + (i*sizeof(unsigned int)), &randint, sizeof(unsigned int));
	}
}

