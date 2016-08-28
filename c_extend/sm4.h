//* Copyright (C) , Zhang Wei, 2014, All rights reserved.
//*
//* SM4 Cryptographic Algorithm of C Code.
//*
//* Author: Zhang Wei <d5c5ceb0@gmail.com>
//* Date: 2014-03-10
//*
//* History: v1.0 initial verision

#ifndef SM4_H_
#define SM4_H_

typedef signed char INT8;
typedef signed short INT16;
typedef signed int INT32;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;


#define SM4_ENCRYPT			0x00
#define SM4_DECRYPT			0x01

void SM4_ECB_32(UINT32 *o, UINT32 *i, UINT32 *k, UINT8 mode);
void SM4_ECB(UINT8 *o, UINT8 *i, UINT8 *k, UINT8 mode);

#endif
