/* 
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */
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
