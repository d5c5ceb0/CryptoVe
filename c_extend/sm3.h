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


// 类型定义

typedef signed char    INT8;
typedef signed short   INT16;
typedef signed int     INT32;  
typedef unsigned char  UINT8;
typedef unsigned short UINT16;
typedef unsigned int   UINT32;  


#define SM3_BLOCK_LEN 0x40      // SM3块字节长度
#define SM3_256BITS   256       // 输出256位摘要
#define SM3_192BITS   192       // 输出192位摘要
#define SM3_160BITS   160       // 输出160位摘要

typedef struct SM3_CTX_ST
{
    UINT32 type;                // 输出类型: 160位,192位,256位
    UINT32 total_blen[2];       // 输入数据总字节长度
    UINT32 state_vector[8];     // 中间状态缓存
    UINT8  tmp_buf[0x40];       // 不足512位数据缓存  

} SM3_CTX;


void sm3_init(SM3_CTX *ctx, UINT32 type);
void sm3_update(SM3_CTX *ctx, UINT8 *in, UINT32 in_blen);
void sm3_final(SM3_CTX *ctx, UINT8 *digest);

#endif 


