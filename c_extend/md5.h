/* 
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */
#ifndef MD5_H_
#define MD5_H_
/* POINTER defines a generic pointer type */
typedef unsigned char * POINTER;

/* UINT2 defines a two byte word */
//typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
typedef unsigned int UINT4;


/* MD5 context. */
typedef struct {
	UINT4 state[4];                                   /* state (ABCD) */
	UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void MD5Init (MD5_CTX *context);
void MD5Update (MD5_CTX *context, unsigned char *input, unsigned int inputLen);
void MD5Final (unsigned char digest[16], MD5_CTX *context);

#endif
