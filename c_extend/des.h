#ifndef _DES_H_
#define _DES_H_


//DESº”√‹£¨ out 8 byte, in 8 byte, key 8 byte
void Des_Encrypt(unsigned char *out, unsigned char *in, unsigned char *key);
void Des_Decrypt(unsigned char *out, unsigned char *in, unsigned char *key);
void Key_GenSubKey(unsigned char *out, unsigned char *in);
#endif
