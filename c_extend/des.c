/* 
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */

#include "des.h"

unsigned char Key_PC1[56] = {
  57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4,
};
unsigned char Key_PC2[48] = {
  14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
  23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};
unsigned char Key_Rotate_L[16] = {
   1,  1,  2,  2,  2,  2,  2,  2, 1,  2,  2,  2,  2,  2,  2,  1
};

unsigned char Data_IP[64] = {
  58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
  62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
  57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
  61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7
};

unsigned char Data_EBox[48] = {
  32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9, 10, 11,
  12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
  22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1,
};
unsigned char Data_SBox[8][64] = {
  {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
   0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
   4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
  15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,}
,
  {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
   3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
   0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
  13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,}
,
{ 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
  13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
  13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
   1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,}
,
  {7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
  13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2,  12, 1, 10, 14,  9,
  10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
   3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,}
,
   {2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
  14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
   4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
  11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,}
,
  {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
  10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
   9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
   4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,}
,
   {4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
  13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
   1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
   6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,}
,
  {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
   1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
   7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
   2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
};

unsigned char Data_PBox[32] = {
  16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
   2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

unsigned char Data_Inv_IP[64] = {
  40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
  38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
  36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
  34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41, 9,  49, 17, 57, 25
};

//初始置换out 56 byte, in 8 byte.
 void Key_Perm_Choice(unsigned char *out, unsigned char *in)
{
  int i, j;
  unsigned char TempBuf[64];

  //将字节拆分成位, 8 bytes->64 bits
  for(i=0; i<8; i++)
    for(j=0; j<8; j++)
      TempBuf[i*8+j] = (in[i]>>(7-j))&0x01;

  //置换选择
  for(i=0; i<56; i++) {
    out[i] = TempBuf[(Key_PC1[i]-1)];    //0~27, for left
  }
}

//循环左移 out 56 byte, in 56 byte, round 第几轮
 void Key_Rotate_Left(unsigned char *out, unsigned char *in, int round)
{
  int i;
  unsigned char TempBuf[28];

  //循环左移
  for(i=0; i<28; i++)
    TempBuf[i] = in[(i+Key_Rotate_L[round])%28];

  for(i=0; i<28; i++)
    out[i] = TempBuf[i];
}

//密钥选择 out 48 byte, in 56 byte
 void Key_Perm_Choice2(unsigned char *out, unsigned char *in)
{
  int i;

  for(i=0; i<48; i++)
    out[i] = in[Key_PC2[i]-1];
}

//out 48*16 byte, in 8 byte
void Key_GenSubKey(unsigned char *out, unsigned char *in)
{
  unsigned char TempBuf[56];
  int i;

  //初始选择PC_1
  Key_Perm_Choice(TempBuf, in);

  //移位和选择
  for(i=0; i<16; i++) {
    Key_Rotate_Left(TempBuf, TempBuf, i);
    Key_Rotate_Left(TempBuf+28, TempBuf+28, i);
    Key_Perm_Choice2(out+48*i, TempBuf);
  }
}

//DES初始置换, out 64 byte, in 8 byte
 void Des_Init_Perm(unsigned char *out, unsigned char *in)
{
  unsigned char TempBuf[64];
  int i, j;

  //将字节拆分成位, 8 bytes->64 bits
  for(i=0; i<8; i++)
    for(j=0; j<8; j++)
      TempBuf[i*8+j] = (in[i]>>(7-j))&0x01;

  //初始置换
  for(i=0; i<64; i++)
    out[i] = TempBuf[Data_IP[i]-1];

}

  //DES扩展置换 out 48 byte, in 32 byte
 void Des_Expans_Perm(unsigned char *out, unsigned char *in)
{
  int i;

  for(i=0; i<48; i++)
    out[i] = in[Data_EBox[i]-1];
}

//DES代换，out 32 byte, in 48 byte
 void Des_Substitution(unsigned char *out, unsigned char *in)
{
  unsigned char row;
  unsigned char col;
  unsigned char tempBuf[8];
  int i, j;

  for(i=0; i<8; i++){
    row = (in[i*6]<<1) | in[i*6+5];
    col = (in[i*6+1]<<3) | (in[i*6+2]<<2) | (in[i*6+3]<<1) | in[i*6+4];
    tempBuf[i] = Data_SBox[i][row*16+col];
  }

  for(i=0; i<8; i++)
    for(j=0; j<4; j++)
      out[i*4+j] = (tempBuf[i]>>(3-j))&0x01;
}

//DES置换，out 32 byte, in 32 byte
 void Des_Permutation(unsigned char *out, unsigned char *in)
{
  int i;

  for(i=0; i<32; i++)
    out[i] = in[Data_PBox[i]-1];
}

//DES异或，out blen byte, in blen byte
 void Des_Xor(unsigned char *out, unsigned char *in1, unsigned char *in2, int blen)
{
  int i;
  for(i=0; i<blen; i++)
    out[i] = in1[i] ^ in2[i];
}

//DES函数f，out 32 byte, in 32 byte, key 48 byte
 void Des_Func_F(unsigned char *out, unsigned char *in, unsigned char *key/*, int c*/)
{

  unsigned char tempBuf[48];
  unsigned char tempBuf2[32];

  Des_Expans_Perm(tempBuf, in);
  Des_Xor(tempBuf, tempBuf, key, 48);
  Des_Substitution(tempBuf2, tempBuf);
/*  if(c==14)
  {
      for(i=0; i<32; i++)
        out[i] = tempBuf2[i];
        return;
  }
*/  Des_Permutation(out, tempBuf2);
}

//DES逆置换，out 64 byte, in 64 byte
 void Des_Final_Perm(unsigned char *out, unsigned char *in)
{
  int i;

  for(i=0; i<64; i++)
    out[i] = in[Data_Inv_IP[i]-1];
}

//DES加密， out 8 byte, in 8 byte, key 8 byte
void Des_Func(unsigned char *out, unsigned char *in, unsigned char *key)
{
  unsigned char tempBuf[64];
  unsigned char tempBuf2[32];
  unsigned char tempBuf3[32];
  unsigned char tempBuf4[64];
  int i, j;

  //初始置换
  Des_Init_Perm(tempBuf, in);

  //16轮操作
  for(i=0; i<16; i++) {
    Des_Func_F(tempBuf2, &tempBuf[32], key+48*i/*, i*/);
/*    if(i == 14)
     {

     for(j=0; j<32; j++)
            out[j] = tempBuf2[j];
    return;
     }
  */  for(j=0; j<32; j++)
      tempBuf3[j] = tempBuf[32+j];

    Des_Xor(&tempBuf[32], &tempBuf[0], tempBuf2, 32);

    for(j=0; j<32; j++)
      tempBuf[j] = tempBuf3[j];

/*    for(j=0; j<64; j++)
      out[j] = tempBuf[j];
    if(i == 15)
        return;
*/  }
  for(i=0; i<32; i++)
  {
    tempBuf2[0]= tempBuf[i];
    tempBuf[i] = tempBuf[i+32];
    tempBuf[i+32] = tempBuf2[0];
  }

  Des_Final_Perm(tempBuf4, tempBuf);

  for(i=0; i<8; i++)
      out[i] = (tempBuf4[i*8]<<7) | (tempBuf4[i*8+1]<<6) | \
                   (tempBuf4[i*8+2]<<5) | (tempBuf4[i*8+3]<<4) | \
                   (tempBuf4[i*8+4]<<3) | (tempBuf4[i*8+5]<<2) | \
                   (tempBuf4[i*8+6]<<1) | tempBuf4[i*8+7];

}

void Des_Encrypt(unsigned char *out, unsigned char *in, unsigned char *key)
{
	unsigned char key1[768];
	Key_GenSubKey(key1, key);
	Des_Func(out, in, key1);
}

void Des_Decrypt(unsigned char *out, unsigned char *in, unsigned char *key)
{
	unsigned char key1[768];
	unsigned char key2[768];
	int i, j;

	Key_GenSubKey(key1, key);
	for(i=0; i<16;i++)
		for(j=0; j<48;j++)
			key2[i*48+j] = key1[(15-i)*48+j];
	Des_Func(out, in, key2);
}
