/* 
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */
#ifndef SM3_H_
#define SM3_H_


typedef signed char    INT8;
typedef signed short   INT16;
typedef signed int     INT32;  
typedef unsigned char  UINT8;
typedef unsigned short UINT16;
typedef unsigned int   UINT32;  


#define SM3_BLOCK_LEN 0x40    
#define SM3_256BITS   256    
#define SM3_192BITS   192   
#define SM3_160BITS   160  

typedef struct SM3_CTX_ST
{
    UINT32 type;               
    UINT32 total_blen[2];     
    UINT32 state_vector[8];  
    UINT8  tmp_buf[0x40];   

} SM3_CTX;


void sm3_init(SM3_CTX *ctx, UINT32 type);
void sm3_update(SM3_CTX *ctx, UINT8 *in, UINT32 in_blen);
void sm3_final(SM3_CTX *ctx, UINT8 *digest);

#endif 


