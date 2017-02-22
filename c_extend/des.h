/* 
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */
#ifndef _DES_H_
#define _DES_H_


//DES encrypt out 8 byte, in 8 byte, key 8 byte
void Des_Encrypt(unsigned char *out, unsigned char *in, unsigned char *key);
void Des_Decrypt(unsigned char *out, unsigned char *in, unsigned char *key);
void Key_GenSubKey(unsigned char *out, unsigned char *in);
#endif
