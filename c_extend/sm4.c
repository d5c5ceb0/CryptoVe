//* Copyright (C) , Zhang Wei, 2014, All rights reserved.
//*
//* SM4 Cryptographic Algorithm of C Code.
//*
//* Author: Zhang Wei <d5c5ceb0@gmail.com>
//* Date: 2014-03-10
//*
//* History:
//*
#include "sm4.h"

static UINT32 SM4_FK[4]=
{
0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc
};

static UINT32 SM4_CK[32]=
{
0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

static UINT32 SM4_Sbox[256] =
{
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// 循环左移
UINT32 SM4_RotL(UINT32 x, UINT8 i)
{
    return (x<<i)|(x>>(32-i));
}

// 非线性变换t
UINT32 SM4_TAO(UINT32 a)
{
    return SM4_Sbox[(UINT8)a] | (SM4_Sbox[(UINT8)(a>>8)]<<8) | (SM4_Sbox[(UINT8)(a>>16)]<<16) | (SM4_Sbox[(UINT8)(a>>24)]<<24);
}

// 线性变换L
UINT32 SM4_L(UINT32 b)
{
    return b ^ SM4_RotL(b, 2) ^ SM4_RotL(b, 10) ^ SM4_RotL(b, 18) ^ SM4_RotL(b, 24);
}

// 合成置换T
UINT32 SM4_T(UINT32 x)
{
    return SM4_L(SM4_TAO(x));
}


// 轮函数F
UINT32 SM4_F(UINT32 x0, UINT32 x1, UINT32 x2, UINT32 x3, UINT32 rk)
{
    return x0 ^ SM4_T(x1 ^ x2 ^ x3 ^ rk);
}
// 反序变换R
void SM4_R(UINT32 *o, UINT32 *i)
{
    o[0] = i[3];
    o[1] = i[2];
    o[2] = i[1];
    o[3] = i[0];

    return;
}

// 密钥线性变换L
UINT32 SM4_KL(UINT32 b)
{
    return b ^ SM4_RotL(b, 13) ^ SM4_RotL(b, 23);
}

// 密钥的合成置换T
UINT32 SM4_KT(UINT32 x)
{
    return SM4_KL(SM4_TAO(x));
}

// 密钥扩展KX
void SM4_KX(UINT32 *rk, UINT32 *mk)
{
    UINT32 k[4];
    UINT8 i;

    k[0] = mk[0]^SM4_FK[0];
    k[1] = mk[1]^SM4_FK[1];
    k[2] = mk[2]^SM4_FK[2];
    k[3] = mk[3]^SM4_FK[3];


    for(i = 0; i < 32; i++)
    {
        rk[i] = k[0] ^ SM4_KT(k[1] ^ k[2] ^ k[3] ^ SM4_CK[i]);
        k[0] = k[1];
        k[1] = k[2];
        k[2] = k[3];
        k[3] = rk[i];
    }

    return;
}

void SM4_ECB_32(UINT32 *o, UINT32 *i, UINT32 *k, UINT8 mode)
{
    UINT8 j;
    UINT32 tmp;
    UINT32 rk[32];
    UINT32 m[4];

    m[0] = i[0];
    m[1] = i[1];
    m[2] = i[2];
    m[3] = i[3];

    SM4_KX(rk, k);

    if(mode == 0)   //加密
    {
        for(j = 0; j < 32; j++)
        {
            tmp = SM4_F(m[0], m[1], m[2], m[3], rk[j]);
            m[0] = m[1];
            m[1] = m[2];
            m[2] = m[3];
            m[3] = tmp;
         }
    }
    else
    {
         for(j = 32; j > 0; j--)
        {
            tmp = SM4_F(m[0], m[1], m[2], m[3], rk[j-1]);
            m[0] = m[1];
            m[1] = m[2];
            m[2] = m[3];
            m[3] = tmp;
         }
    }

    SM4_R(o, m);

    return;
}

void SM4_ECB(UINT8 *o, UINT8 *i, UINT8 *k, UINT8 mode)
{
    INT32 j;
    UINT32 m[4];
    UINT32 key[4];
    UINT32 c[4];

    m[0] = (i[0]<<24)|(i[1]<<16)|(i[2]<<8)|i[3];
    m[1] = (i[4]<<24)|(i[5]<<16)|(i[6]<<8)|i[7];
    m[2] = (i[8]<<24)|(i[9]<<16)|(i[10]<<8)|i[11];
    m[3] = (i[12]<<24)|(i[13]<<16)|(i[14]<<8)|i[15];

    key[0] = (k[0]<<24)|(k[1]<<16)|(k[2]<<8)|k[3];
    key[1] = (k[4]<<24)|(k[5]<<16)|(k[6]<<8)|k[7];
    key[2] = (k[8]<<24)|(k[9]<<16)|(k[10]<<8)|k[11];
    key[3] = (k[12]<<24)|(k[13]<<16)|(k[14]<<8)|k[15];

    SM4_ECB_32(c, m, key, mode);

    for(j = 0; j < 4; j++)
    {
        o[j*4] = (UINT8)(c[j]>>24);
        o[j*4+1] = (UINT8)(c[j]>>16);
        o[j*4+2] = (UINT8)(c[j]>> 8);
        o[j*4+3] = (UINT8)(c[j]);
    }

    return;
}
