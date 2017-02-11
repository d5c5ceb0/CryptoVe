//* Copyright (C) , Zhang Wei, 2014, All rights reserved.
//*
//* SM4 Cryptographic Algorithm of C Code.
//*
//* Author: Zhang Wei <d5c5ceb0@gmail.com>
//* Date: 2014-03-10
//*
//* History: v1.0 initial verision

#ifndef SM3_H_
#define SM3_H_


// ���Ͷ���

typedef signed char    INT8;
typedef signed short   INT16;
typedef signed int     INT32;  
typedef unsigned char  UINT8;
typedef unsigned short UINT16;
typedef unsigned int   UINT32;  


#define SM3_BLOCK_LEN 0x40      // SM3���ֽڳ���
#define SM3_256BITS   256       // ���256λժҪ
#define SM3_192BITS   192       // ���192λժҪ
#define SM3_160BITS   160       // ���160λժҪ

typedef struct SM3_CTX_ST
{
    UINT32 type;                // �������: 160λ,192λ,256λ
    UINT32 total_blen[2];       // �����������ֽڳ���
    UINT32 state_vector[8];     // �м�״̬����
    UINT8  tmp_buf[0x40];       // ����512λ���ݻ���  

} SM3_CTX;


void sm3_init(SM3_CTX *ctx, UINT32 type);
void sm3_update(SM3_CTX *ctx, UINT8 *in, UINT32 in_blen);
void sm3_final(SM3_CTX *ctx, UINT8 *digest);

#endif 


