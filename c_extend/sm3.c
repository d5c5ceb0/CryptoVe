/* 
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */
#include "sm3.h"
#include <stdio.h>
#include <stdlib.h>

#undef _DEBUG

#ifndef SM3_T

#define SM3_T(j)  (((j) / 16) ? 0x7A879D8A : 0x79CC4519)

#endif

extern UINT32 SM3_FF(UINT32 x, UINT32 y, UINT32 z, UINT32 j)
{
    if(j / 16)
        return ((x | y) & (x | z) & (y | z));
    else
        return x ^ y ^ z;
}

extern UINT32 SM3_GG(UINT32 x, UINT32 y, UINT32 z, UINT32 j)
{
    if(j / 16)
        return ((x & y) | ((~x) & z));
    else
        return x ^ y ^ z;
}

extern UINT32 SM3_ROL(UINT32 x, UINT8 n)
{
    return (x << n) | (x >> (32 - n));
}

extern UINT32 SM3_P0(UINT32 x)
{
    return x ^ SM3_ROL(x, 9) ^ SM3_ROL(x, 17);
}

extern UINT32 SM3_P1(UINT32 x)
{
    return x ^ SM3_ROL(x, 15) ^ SM3_ROL(x, 23);
}

extern void SM3_Wj(UINT32 *W, UINT32 *W1, UINT8 *B)
{
    UINT32 j = 0;
    
    for(j = 0; j < 16; j++)
        W[j] = (B[j * 4] << 24) | (B[j * 4 + 1] << 16) | (B[j * 4 + 2] << 8) | B[j * 4 + 3];

    for(j = 16; j < 68; j++)
        W[j] = SM3_P1(W[j - 16] ^ W[j - 9] ^ SM3_ROL(W[j - 3], 15)) ^ SM3_ROL(W[j - 13], 7) ^ W[j - 6];

    for(j=0; j<64; j++)
        W1[j] = W[j] ^ W[j + 4];

#ifdef _DEBUG
	for(j = 0; j < 16; j++)
	{
		printf("%08x ", W[j]);
		if((j + 1) % 8 == 0)
			printf("\n");
	}

	printf("W0,W1,...,W67\n");
	for(j = 0; j < 68; j++)
	{
		printf("%08x ", W[j]);
		if((j + 1) % 8 == 0)
			printf("\n");
	}
	printf("\n");
	printf("W'0,W'1,...,W'67\n");
	for(j = 0; j < 64; j++)
	{
		printf("%08x ", W1[j]);
		if((j + 1) % 8 == 0)
			printf("\n");
	}
#endif

    return ;
}


extern void SM3_CF(UINT32 *V, UINT8 *I)
{
	UINT32 j;
    UINT32 A,B,C,D,E,F,G,H;
    UINT32 SS1, SS2, TT1, TT2;
    UINT32 W[68], W1[64];


    SM3_Wj(W, W1, (UINT8 *)I);

    A = V[0];
    B = V[1];
    C = V[2];
    D = V[3];
    E = V[4];
    F = V[5];
    G = V[6];
    H = V[7];

#ifdef _DEBUG
	printf("-----A--------B--------C--------D--------E--------F--------G--------H-------\n");
#endif

    for(j=0; j<64; j++)
    {
        SS1 = SM3_ROL( (SM3_ROL(A, 12) + E + SM3_ROL(SM3_T(j), (UINT8)j)), 7);
        SS2 = SS1 ^ SM3_ROL(A, 12);
        TT1 = SM3_FF(A, B, C, j) + D + SS2 + W1[j];
        TT2 = SM3_GG(E, F, G, j) + H + SS1 + W[j];
        D = C;
        C = SM3_ROL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = SM3_ROL(F, 19);
        F = E;
        E = SM3_P0(TT2);

#ifdef _DEBUG
		printf("%02x | %08x %08x %08x %08x %08x %08x %08x %08x", j, A, B, C, D, E, F, G, H);
		printf("\n");
#endif
    }

     V[0] ^= A;
     V[1] ^= B;
     V[2] ^= C;
     V[3] ^= D;
     V[4] ^= E;
     V[5] ^= F;
     V[6] ^= G;
     V[7] ^= H;

#ifdef _DEBUG
		printf("XOR| %08x %08x %08x %08x %08x %08x %08x %08x", V[0], V[1], V[2], V[3], V[4], V[5], V[6], V[7]);
		printf("\n");
#endif
     return;
}

void sm3_init(SM3_CTX *ctx, UINT32 type)
{

    ctx->total_blen[0] = 0;
    ctx->total_blen[1] = 0;
    
    ctx->type = type;

    ctx->state_vector[0] = 0x7380166F;
    ctx->state_vector[1] = 0x4914B2B9;
    ctx->state_vector[2] = 0x172442D7;
    ctx->state_vector[3] = 0xDA8A0600;
    ctx->state_vector[4] = 0xA96F30BC;
    ctx->state_vector[5] = 0x163138AA;
    ctx->state_vector[6] = 0xE38DEE4D;
    ctx->state_vector[7] = 0xB0FB0E4E;
}

void sm3_update(SM3_CTX *ctx, UINT8 *in, UINT32 in_blen)
{
    UINT32 i;
    UINT32 left, need;

    left = ctx->total_blen[0]&0x3F;
    need = 64-left;

    ctx->total_blen[0] += in_blen;

    if(ctx->total_blen[0] < in_blen)
        ctx->total_blen[1]++;

    if(in_blen >= need)
    {
		for(i=0; i<need; i++)
			ctx->tmp_buf[left+i] = in[i];
		SM3_CF(ctx->state_vector, ctx->tmp_buf);
        in += need;
        in_blen -= need;
        left = 0;
    }

    while(in_blen>=64)
    {
        SM3_CF(ctx->state_vector, in);
        in += 64;
        in_blen -= 64;
    }

    for(i=0; i<in_blen; i++)
    {
        ctx->tmp_buf[left+i] = in[i];    
    }

    return;
}

void sm3_final(SM3_CTX *ctx, UINT8 *digest)
{
    UINT32 i;
    UINT32 left_len, high, low;

    left_len = ctx->total_blen[0]&(SM3_BLOCK_LEN-1);

    low  = ( ctx->total_blen[0] <<  3 );
    high = ( ctx->total_blen[0] >> 29 ) | ( ctx->total_blen[1] << 3 );

    ctx->tmp_buf[left_len] = 0x80;
    for(i=left_len+1; i<SM3_BLOCK_LEN; i++)
        ctx->tmp_buf[i] = 0;
	
	
    if(left_len>=56)
    {
        SM3_CF(ctx->state_vector, ctx->tmp_buf);

        for(i=0; i<SM3_BLOCK_LEN; i++)
            ctx->tmp_buf[i] = 0;
    }

    ctx->tmp_buf[SM3_BLOCK_LEN-4]= (UINT8)(low>>24);
	ctx->tmp_buf[SM3_BLOCK_LEN-3]= (UINT8)(low>>16);
	ctx->tmp_buf[SM3_BLOCK_LEN-2]= (UINT8)(low>>8);
	ctx->tmp_buf[SM3_BLOCK_LEN-1]= (UINT8)(low);
    ctx->tmp_buf[SM3_BLOCK_LEN-8]= (UINT8)(high>>24);
	ctx->tmp_buf[SM3_BLOCK_LEN-7]= (UINT8)(high>>16);
	ctx->tmp_buf[SM3_BLOCK_LEN-6]= (UINT8)(high>>8);
	ctx->tmp_buf[SM3_BLOCK_LEN-5]= (UINT8)(high);

    SM3_CF(ctx->state_vector, ctx->tmp_buf);

	for(i=0; i<ctx->type/32; i++)
	{
		digest[i*4]   = (UINT8)(ctx->state_vector[i]>>24);
		digest[i*4+1] = (UINT8)(ctx->state_vector[i]>>16);
		digest[i*4+2] = (UINT8)(ctx->state_vector[i]>>8);
		digest[i*4+3] = (UINT8)(ctx->state_vector[i]);
	}

#ifdef _DEBUG
	for(i=0; i<8; i++)
	{
		printf("%08x ", ctx->state_vector[i]);
		if((i+1)%8 == 0)
			printf("\n");
	}
	printf("\n");
#endif

    return ;
}

