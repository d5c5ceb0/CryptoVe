#include "sha.h"

typedef     unsigned char		uint8;      // 无符号8位整型变量
typedef     signed   char       int8;       // 有符号8位整型变量
typedef     unsigned short      uint16;     // 无符号16位整型变量
typedef     signed   short      int16;      // 有符号16位整型变量
typedef     unsigned int        uint32;     // 无符号32位整型变量
typedef     signed   int        int32;      // 有符号32位整型变量
typedef     unsigned long long  uint64;
typedef     float               fp32;       // 单精度浮点数（32位长度）
typedef     double              fp64;       // 双精度浮点数（64位长度）



void sha1_update(Hash_CTX256 *ctx, uint8 *input, uint32 length );
void sha1_finish( Hash_CTX256 *ctx, uint8 *digest);
void sha224_update(Hash_CTX256 *ctx, uint8 *message, uint32 len);
void sha224_final(Hash_CTX256 *ctx, uint8 *digest);
void sha256_update(Hash_CTX256 *ctx, uint8 *message, uint32 len);
void sha256_final(Hash_CTX256 *ctx, uint8 *digest);
void sha384_update(Hash_CTX512 *ctx, uint8 *message,uint32 len);
void sha384_final(Hash_CTX512 *ctx, uint8 *digest);
void sha512_update(Hash_CTX512 *ctx, uint8 *message,uint32 len);
void sha512_final(Hash_CTX512 *ctx, uint8 *digest);

#define SHFR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA256_F1(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SHA256_F2(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SHA256_F3(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHFR(x,  3))
#define SHA256_F4(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))


#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}


#define UNPACK64(x, str)                      \
{                                             \
    *((str) + 7) = (uint8) ((x)      );       \
    *((str) + 6) = (uint8) ((x) >>  8);       \
    *((str) + 5) = (uint8) ((x) >> 16);       \
    *((str) + 4) = (uint8) ((x) >> 24);       \
    *((str) + 3) = (uint8) ((x) >> 32);       \
    *((str) + 2) = (uint8) ((x) >> 40);       \
    *((str) + 1) = (uint8) ((x) >> 48);       \
    *((str) + 0) = (uint8) ((x) >> 56);       \
}

#define PACK64(str, x)                        \
{                                             \
    *(x) =   ((uint64) *((str) + 7)      )    \
           | ((uint64) *((str) + 6) <<  8)    \
           | ((uint64) *((str) + 5) << 16)    \
           | ((uint64) *((str) + 4) << 24)    \
           | ((uint64) *((str) + 3) << 32)    \
           | ((uint64) *((str) + 2) << 40)    \
           | ((uint64) *((str) + 1) << 48)    \
           | ((uint64) *((str) + 0) << 56);   \
}



#define SHA256_SCR(i)                         \
{                                             \
    w[i] =  SHA256_F4(w[i -  2]) + w[i -  7]  \
          + SHA256_F3(w[i - 15]) + w[i - 16]; \
}

#define GET_UINT32(n,b,i)               \
{                               \
  (n) = ( (uint32) (b)[(i)   ] << 24 )     \
    | ( (uint32) (b)[(i) + 1] << 16 )     \
    | ( (uint32) (b)[(i) + 2] << 8 )     \
    | ( (uint32) (b)[(i) + 3]     );     \
}

#define PUT_UINT32(n,b,i)               \
{                               \
  (b)[(i)   ] = (uint8) ( (n) >> 24 );     \
  (b)[(i) + 1] = (uint8) ( (n) >> 16 );     \
  (b)[(i) + 2] = (uint8) ( (n) >> 8 );     \
  (b)[(i) + 3] = (uint8) ( (n)     );     \
}

#define SHA224_DIGEST_SIZE ( 224 / 8)
#define SHA256_DIGEST_SIZE ( 256 / 8)
#define SHA384_DIGEST_SIZE ( 384 / 8)
#define SHA512_DIGEST_SIZE ( 512 / 8)

#define SHA256_BLOCK_SIZE  ( 512 / 8)
#define SHA512_BLOCK_SIZE  (1024 / 8)
#define SHA384_BLOCK_SIZE  SHA512_BLOCK_SIZE
#define SHA224_BLOCK_SIZE  SHA256_BLOCK_SIZE

//a 指向数据a 的指针 b 指向数据b的指针  result 指向结果的指针 所有指针都按照小端模式指向
void SHAADD(uint8 *a, uint8 *b, uint8 *result)
{
#if 1
	uint8 tmp_a;
    uint8 tmp_sum;
    uint8 tmp_carry=0;
    int32 i;
    
    for (i = 8; i > 0; i--)
    { 	
    	tmp_a = a[i-1] + tmp_carry;
    	
    	
    	if((tmp_a<a[i-1]) && (tmp_a<tmp_carry))
    	{
    		tmp_carry = 1;
    	}
        else
            tmp_carry = 0;
            
    	tmp_sum = tmp_a + b[i-1];
    	
    	if((tmp_sum<tmp_a) && (tmp_sum<b[i-1]))
    	{
    		tmp_carry = 1;
    	}
    	
    	result[i-1] = tmp_sum;
    }

#else
	uint8 i;
	XBYTE[SXA_CTRL0] = 0x20; //set CLS 1
	XBYTE[SXA_CTRL0] = 0x80; //set add mode 

	a += 0x07; 
	for(i=0;i<8;i++)
	{
		*(P_SXA_DATAA+i) = *a;
		a--;			
	}
	
	b += 0x07;
	for(i=0;i<8;i++)
	{
		*(P_SXA_DATAB+i) = *b;
		b--;
	}
		
	XBYTE[SXA_CTRL0] |= 0x01;
	while(0);

	result += 0x07;
	/*for(i=0;i<8;i++)
	{
		*result = *(P_SXA_RESULT+i);
		result--;
	}*/
	DmaRun(0x01,0x08,(uint16)result&0xff,((uint16)result)>>8,(uint16)P_SXA_RESULT&0xff,((uint16)P_SXA_RESULT)>>8,0x08,0);	
	//result -= 0x07;
#endif
		
}


void SHAXOR(uint8 *a, uint8 *b, uint8 *result)
{
#if 1
	uint8 i;
	for(i=0; i<8; i++)
		result[i] = *a++ ^ *b++;
#else
	uint8 i;
	XBYTE[SXA_CTRL0] = 0x20; //set CLS 1
	XBYTE[SXA_CTRL0] = 0x40; //set xor mode 

	a += 0x07; 
	for(i=0;i<8;i++)
	{
		*(P_SXA_DATAA+i) = *a;
		a--;			
	}

	b += 0x07;
	for(i=0;i<8;i++)
	{
		*(P_SXA_DATAB+i) = *b;
		b--;
	}	

	XBYTE[SXA_CTRL0] |= 0x01;
	while(0);

	result += 0x07;
	/*for(i=0;i<8;i++)
	{
		*result = *(P_SXA_RESULT+i);
		result--;
	}*/
	DmaRun(0x01,0x08,(uint16)result&0xff,((uint16)result)>>8,(uint16)P_SXA_RESULT&0xff,((uint16)P_SXA_RESULT)>>8,0x08,0);		
	//result -= 0x07;
#endif
}


void SHAAND(uint8 *a, uint8 *b, uint8 *result)
{
#if 1
	uint8 i;
	for(i=0; i<8; i++)
		result[i] = *a++ & *b++;
#else
	uint8 i;
	XBYTE[SXA_CTRL0] = 0x20; //set CLS 1
	XBYTE[SXA_CTRL0] = 0xC0; //set and mode 

	a += 0x07; 
	for(i=0;i<8;i++)
	{
		*(P_SXA_DATAA+i) = *a;
		a--;			
	}

	b += 0x07;
	for(i=0;i<8;i++)
	{
		*(P_SXA_DATAB+i) = *b;
		b--;
	}	

	XBYTE[SXA_CTRL0] |= 0x01;
	while(0);

	result += 0x07;
	/*for(i=0;i<8;i++)
	{
		*result = *(P_SXA_RESULT+i);
		result--;
	}*/
	DmaRun(0x01,0x08,(uint16)result&0xff,((uint16)result)>>8,(uint16)P_SXA_RESULT&0xff,((uint16)P_SXA_RESULT)>>8,0x08,0);	
	//result -= 0x07;	
#endif
}

void ROL32(uint32 *out, uint32 x, uint8 n)
{
    *out = (x << n) | (x >> (32 - n));
}

void ROL64(uint64* out, uint64 x, uint8 n)
{
    *out = (x << n) | (x >> (64 - n));
}

void SHASHIFT(uint8 *a, uint8 len, uint8 model, uint8 *result)
{
#if 1

	uint32 a1;
	uint64 tmp;
    
	if(model == 1)   //model =1 32bit  
	{
        GET_UINT32(a1,a,0);
		ROL32(&a1, a1, len);
        PUT_UINT32(a1,result,0);
	}
	else if(model == 0)	//64bit
	{
 //       GET_UINT32(a2[0],a,4);
 //       GET_UINT32(a2[1],a,0);
//		ROL64(r, a2, len);
 //       PUT_UINT32(r[0],result,0);
//        PUT_UINT32(r[1],result,4);
		PACK64(a, &tmp);
		ROL64(&tmp, tmp, len);
		UNPACK64(tmp, result);
	}
#else
	uint8 i;
	XBYTE[SXA_CTRL0] = 0x20; //set CLS 1
	XBYTE[SXA_CTRL0] = 0x00; //set shift mode 

	XBYTE[SXA_CTRL1] = 0x00;
	XBYTE[SXA_CTRL1] = (model<<8) +len;

	if(model == 1)   //model =1 32bit  
	{
		//32bit
		a += 0x04; 
		for(i=0;i<4;i++)
		{
			*(P_SXA_DATAB+i) = *a;
			a--;			
		}
	}
	else if(model == 0)
	{
		//64bit
		a += 0x07; 
		for(i=0;i<8;i++)
		{
			*(P_SXA_DATAB+i) = *a;
			a--;			
		}
	}

	XBYTE[SXA_CTRL0] |= 0x01;
	while(0);

	if(model)
	{
		//32bit
		result += 0x04;
		/*for(i=0;i<4;i++)
		{
			*result = *(P_SXA_RESULT+i);
			result--;
		}*/
		DmaRun(0x01,0x08,(uint16)result&0xff,((uint16)result)>>8,(uint16)P_SXA_RESULT&0xff,((uint16)P_SXA_RESULT)>>8,0x04,0);		
	}
	else
	{
		//64bit
		result += 0x07;
		/*for(i=0;i<8;i++)
		{
			*result = *(P_SXA_RESULT+i);
			result--;
		}*/
		DmaRun(0x01,0x08,(uint16)result&0xff,((uint16)result)>>8,(uint16)P_SXA_RESULT&0xff,((uint16)P_SXA_RESULT)>>8,0x08,0);	
	}
#endif
}


void SHANOT(uint8 *a,uint8 *Result)
{
	 uint8 i;
	 for(i=0;i<8;i++)
	 {
	 	*Result = ~(*a);
		a++;
		Result++;
	 }
}


void memcpy1( uint8* pdst,const uint8* psrc,uint32 uLen )
{
	uint32 i;
	for(i=0;i<uLen;i++)
	{
		*pdst++ = *psrc++;
	}
}

void memset1( uint8* pdst,uint8 val, uint32 uLen )
{
	uint32 i=0;
	for(i=0;i<uLen;i++)
	{
		*pdst++=val;
	}
}


//Hash_mode: 1:SHA1,2:SHA224,3:SHA256,
uint8 Hash_Init(Hash_CTX256 *HashCtx,uint8 Hash_mode)
{
	if(Hash_mode == 0x01)
	{
	 	HashCtx->Result[0] = 0x67452301;	//低
		HashCtx->Result[1] = 0xefcdab89;
		HashCtx->Result[2] = 0x98badcfe;
		HashCtx->Result[3] = 0x10325476;
		HashCtx->Result[4] = 0xc3d2e1f0;	//高

		HashCtx->Len = 0x00;
		HashCtx->TotalLen[0] = 0x00;
	    HashCtx->TotalLen[1] = 0x00;
		HashCtx->AlgFlag = Hash_mode;
	}
	else if(Hash_mode == 0x02)
	{
	   	HashCtx->Result[0] = 0xc1059ed8;	 //低
		HashCtx->Result[1] = 0x367cd507;
		HashCtx->Result[2] = 0x3070dd17;
		HashCtx->Result[3] = 0xf70e5939;
		HashCtx->Result[4] = 0xffc00b31;
		HashCtx->Result[5] = 0x68581511;
		HashCtx->Result[6] = 0x64f98fa7;
		HashCtx->Result[7] = 0xbefa4fa4;
		
		HashCtx->Len = 0x00;
		HashCtx->TotalLen[0] = 0x00;
	    HashCtx->TotalLen[1] = 0x00;
		HashCtx->AlgFlag = Hash_mode;
	}
	else if(Hash_mode == 0x03)
	{
		HashCtx->Result[0] = 0x6a09e667;	   //低
		HashCtx->Result[1] = 0xbb67ae85;
		HashCtx->Result[2] = 0x3c6ef372;
		HashCtx->Result[3] = 0xa54ff53a;
		HashCtx->Result[4] = 0x510e527f;
		HashCtx->Result[5] = 0x9b05688c;
		HashCtx->Result[6] = 0x1f83d9ab;
		HashCtx->Result[7] = 0x5be0cd19;		//高
		
		HashCtx->Len = 0x00;
		HashCtx->TotalLen[0] = 0x00;
	    HashCtx->TotalLen[1] = 0x00;
	    HashCtx->AlgFlag = Hash_mode;
 	}
	return 0;	  	 		
}

uint8 Hash_Update(Hash_CTX256 *HashCtx,uint8 *Hash_DataIn,uint32 InLen)
{

	//初始值
	if(HashCtx->AlgFlag == 0x01) //SHA1
	{
		sha1_update(HashCtx, Hash_DataIn, InLen);
	}
	else if(HashCtx->AlgFlag == 0x02) //SHA224
	{
		sha224_update(HashCtx, Hash_DataIn, InLen);
	}
	else if(HashCtx->AlgFlag == 0x03) //SHA256
	{
		sha256_update(HashCtx,Hash_DataIn, InLen);
	}
	return 0;
}

uint8 Hash_Final(Hash_CTX256 *HashCtx, uint8 *Hash_DataOut)
{
	//初始值
	 
	if(HashCtx->AlgFlag == 0x01) //SHA1
	{
		sha1_finish(HashCtx, Hash_DataOut);
	}
	else if(HashCtx->AlgFlag == 0x02)  //SHA224
	{
		sha224_final(HashCtx, Hash_DataOut);
	}
	else if(HashCtx->AlgFlag == 0x03) //SHA256
	{
		sha256_final(HashCtx, Hash_DataOut);
	}
	return 0;	 
}


//Hash_mode  4:SHA384,5:SHA512
uint8 Hash_Init1(Hash_CTX512 *HashCtx,uint8 Hash_mode)
{
	uint8 i,j;
	/*
	uint32 sha384_h0[16] =
            {0xcbbb9d5d,0xc1059ed8, 0x629a292a,0x367cd507,
             0x9159015a,0x3070dd17, 0x152fecd8,0xf70e5939,
             0x67332667,0xffc00b31, 0x8eb44a87,0x68581511,
             0xdb0c2e0d,0x64f98fa7, 0x47b5481d,0xbefa4fa4};

	uint32 sha512_h0[16] =
            {0x6a09e667,0xf3bcc908, 0xbb67ae85,0x84caa73b,
             0x3c6ef372,0xfe94f82b, 0xa54ff53a,0x5f1d36f1,
             0x510e527f,0xade682d1, 0x9b05688c,0x2b3e6c1f,
             0x1f83d9ab,0xfb41bd6b, 0x5be0cd19,0x137e2179};
	*/
	uint8 sha384_Result0[8][8] =
	{
		0xcb,0xbb,0x9d,0x5d,0xc1,0x05,0x9e,0xd8,
		0x62,0x9a,0x29,0x2a,0x36,0x7c,0xd5,0x07,
		0x91,0x59,0x01,0x5a,0x30,0x70,0xdd,0x17,
		0x15,0x2f,0xec,0xd8,0xf7,0x0e,0x59,0x39,
		0x67,0x33,0x26,0x67,0xff,0xc0,0x0b,0x31,
		0x8e,0xb4,0x4a,0x87,0x68,0x58,0x15,0x11,
		0xdb,0x0c,0x2e,0x0d,0x64,0xf9,0x8f,0xa7,
		0x47,0xb5,0x48,0x1d,0xbe,0xfa,0x4f,0xa4,
	};
	uint8 sha512_Result0[8][8] =
	{
		0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
		0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
		0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
		0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
		0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
		0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
		0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
		0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79,
	};
	if(Hash_mode == 0x04)			       //SHA384
	{
		for (i = 0; i < 8; i++) 
		{
        	for(j = 0; j < 8; j++)
			{
				HashCtx->Result[i][j] = sha384_Result0[i][j];
			}
		}
		HashCtx->Len = 0x00;
		HashCtx->TotalLen[0] = 0x00;
	    HashCtx->TotalLen[1] = 0x00;
	    HashCtx->AlgFlag = Hash_mode;
	}
	else if(Hash_mode == 0x05)				  //SHA512
	{
	   	for (i = 0; i < 8; i++) 
		{
        	for(j = 0; j < 8; j++)
			{
				HashCtx->Result[i][j] = sha512_Result0[i][j];
			}
		}
		
		HashCtx->Len = 0x00;
		HashCtx->TotalLen[0] = 0x00;
	    HashCtx->TotalLen[1] = 0x00;
	    HashCtx->AlgFlag = Hash_mode;
	}
	return 0;	  	 		
}

uint8 Hash_Update1(Hash_CTX512 *HashCtx,uint8 *Hash_DataIn,uint32 InLen)
{
 	if(HashCtx->AlgFlag == 0x04) //SHA384
	{
		sha384_update(HashCtx,Hash_DataIn, InLen);
	}
	else if(HashCtx->AlgFlag == 0x05) //SHA512
	{
		sha512_update(HashCtx,Hash_DataIn, InLen);
	}
	return 0;
}

uint8 Hash_Final1(Hash_CTX512 *HashCtx, uint8 *Hash_DataOut)
{
	if(HashCtx->AlgFlag == 0x04)  //SHA384
	{
		sha384_final(HashCtx, Hash_DataOut);
	}
	else if(HashCtx->AlgFlag == 0x05)  //SHA512
	{
		sha512_final(HashCtx, Hash_DataOut);
	}
	return 0;
}

void sha256_transf(Hash_CTX256 *ctx, uint8 *message, uint32 block_nb)
{
	const uint32 sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

	    uint32 w[64];
	    uint32 wv[8];
	    uint32 t1, t2;
	    const uint8 *sub_block;
	    uint32 i;
		uint32 j;
	
	for (i = 0; i < block_nb; i++) 
	{
        sub_block = message + (i << 6);

        for (j = 0; j < 16; j++) 
		{
            PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++) 
		{
            SHA256_SCR(j);
        }
        for (j = 0; j < 8; j++) 
		{
            wv[j] = ctx->Result[j];
        }
        for (j = 0; j < 64; j++) 
		{
            t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->Result[j] += wv[j];
        }
    }
}

void sha256_update(Hash_CTX256 *ctx, uint8 *message, uint32 len)
{
    uint32 block_nb;
    uint32 new_len, rem_len, tmp_len;
    uint8 *shifted_message;
	
    tmp_len = SHA256_BLOCK_SIZE - ctx->Len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy1((uint8 *)&ctx->TempBuf[ctx->Len], message, rem_len);

    if(ctx->Len + len < SHA256_BLOCK_SIZE) 
	{
        ctx->Len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->TempBuf, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy1(ctx->TempBuf, &shifted_message[block_nb << 6],
           rem_len);

    ctx->Len = rem_len;
    ctx->TotalLen[0] += (block_nb + 1) << 6;
}

void sha256_final(Hash_CTX256 *ctx, uint8 *digest)
{
    uint32 block_nb;
   	uint32 pm_len;
    uint32 len_b;

    int32 i;


    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9) < (ctx->Len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->TotalLen[0] + ctx->Len) << 3;
    pm_len = block_nb << 6;

    memset1(ctx->TempBuf + ctx->Len, 0, pm_len - ctx->Len);
    ctx->TempBuf[ctx->Len] = 0x80;
    UNPACK32(len_b, ctx->TempBuf + pm_len - 4);

    sha256_transf(ctx, ctx->TempBuf, block_nb);


    for (i = 0 ; i < 8; i++) {
        UNPACK32(ctx->Result[i], &digest[i << 2]);
    }
}

void sha224_update(Hash_CTX256 *ctx, uint8 *message, uint32 len)
{
    uint32 block_nb;
    uint32 new_len, rem_len, tmp_len;
    uint8 *shifted_message;

	tmp_len = SHA224_BLOCK_SIZE - ctx->Len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy1((uint8 *)&ctx->TempBuf[ctx->Len], message, rem_len);

    if (ctx->Len + len < SHA224_BLOCK_SIZE) {
        ctx->Len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA224_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->TempBuf, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA224_BLOCK_SIZE;

    memcpy1(ctx->TempBuf, &shifted_message[block_nb << 6],
           rem_len);

    ctx->Len = rem_len;
    ctx->TotalLen[0] += (block_nb + 1) << 6;
}

void sha224_final(Hash_CTX256 *ctx, uint8 *digest)
{
    uint32 block_nb;
   	uint32 pm_len;
    uint32 len_b;

    int32 i;

    block_nb = (1 + ((SHA224_BLOCK_SIZE - 9)
                     < (ctx->Len % SHA224_BLOCK_SIZE)));

    len_b = (ctx->TotalLen[0] + ctx->Len) << 3;
    pm_len = block_nb << 6;

    memset1(ctx->TempBuf + ctx->Len, 0, pm_len - ctx->Len);
    ctx->TempBuf[ctx->Len] = 0x80;
    UNPACK32(len_b, ctx->TempBuf + pm_len - 4);

    sha256_transf(ctx, ctx->TempBuf, block_nb);

    for (i = 0 ; i < 7; i++) {
        UNPACK32(ctx->Result[i], &digest[i << 2]);
    }
}


void sha1_process(Hash_CTX256 *ctx, uint8 *tempdata)
{
  uint32 temp, W[16], A, B, C, D, E;

  GET_UINT32( W[0], tempdata, 0 );
  GET_UINT32( W[1], tempdata, 4 );
  GET_UINT32( W[2], tempdata, 8 );
  GET_UINT32( W[3], tempdata, 12 );
  GET_UINT32( W[4], tempdata, 16 );
  GET_UINT32( W[5], tempdata, 20 );
  GET_UINT32( W[6], tempdata, 24 );
  GET_UINT32( W[7], tempdata, 28 );
  GET_UINT32( W[8], tempdata, 32 );
  GET_UINT32( W[9], tempdata, 36 );
  GET_UINT32( W[10], tempdata, 40 );
  GET_UINT32( W[11], tempdata, 44 );
  GET_UINT32( W[12], tempdata, 48 );
  GET_UINT32( W[13], tempdata, 52 );
  GET_UINT32( W[14], tempdata, 56 );
  GET_UINT32( W[15], tempdata, 60 );

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                             \
(                                     \
  temp = W[(t - 3) & 0x0F] ^ W[(t - 8) & 0x0F] ^   \
      W[(t - 14) & 0x0F] ^ W[ t     & 0x0F],     \
  ( W[t & 0x0F] = S(temp,1) )                 \
)

#define P(a,b,c,d,e,x)                       \
{                                     \
  e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);     \
}

  A = ctx->Result[0];
  B = ctx->Result[1];
  C = ctx->Result[2];
  D = ctx->Result[3];
  E = ctx->Result[4];

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

  P( A, B, C, D, E, W[0] );
  P( E, A, B, C, D, W[1] );
  P( D, E, A, B, C, W[2] );
  P( C, D, E, A, B, W[3] );
  P( B, C, D, E, A, W[4] );
  P( A, B, C, D, E, W[5] );
  P( E, A, B, C, D, W[6] );
  P( D, E, A, B, C, W[7] );
  P( C, D, E, A, B, W[8] );
  P( B, C, D, E, A, W[9] );
  P( A, B, C, D, E, W[10] );
  P( E, A, B, C, D, W[11] );
  P( D, E, A, B, C, W[12] );
  P( C, D, E, A, B, W[13] );
  P( B, C, D, E, A, W[14] );
  P( A, B, C, D, E, W[15] );
  P( E, A, B, C, D, R(16) );
  P( D, E, A, B, C, R(17) );
  P( C, D, E, A, B, R(18) );
  P( B, C, D, E, A, R(19) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

  P( A, B, C, D, E, R(20) );
  P( E, A, B, C, D, R(21) );
  P( D, E, A, B, C, R(22) );
  P( C, D, E, A, B, R(23) );
  P( B, C, D, E, A, R(24) );
  P( A, B, C, D, E, R(25) );
  P( E, A, B, C, D, R(26) );
  P( D, E, A, B, C, R(27) );
  P( C, D, E, A, B, R(28) );
  P( B, C, D, E, A, R(29) );
  P( A, B, C, D, E, R(30) );
  P( E, A, B, C, D, R(31) );
  P( D, E, A, B, C, R(32) );
  P( C, D, E, A, B, R(33) );
  P( B, C, D, E, A, R(34) );
  P( A, B, C, D, E, R(35) );
  P( E, A, B, C, D, R(36) );
  P( D, E, A, B, C, R(37) );
  P( C, D, E, A, B, R(38) );
  P( B, C, D, E, A, R(39) );

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

  P( A, B, C, D, E, R(40) );
  P( E, A, B, C, D, R(41) );
  P( D, E, A, B, C, R(42) );
  P( C, D, E, A, B, R(43) );
  P( B, C, D, E, A, R(44) );
  P( A, B, C, D, E, R(45) );
  P( E, A, B, C, D, R(46) );
  P( D, E, A, B, C, R(47) );
  P( C, D, E, A, B, R(48) );
  P( B, C, D, E, A, R(49) );
  P( A, B, C, D, E, R(50) );
  P( E, A, B, C, D, R(51) );
  P( D, E, A, B, C, R(52) );
  P( C, D, E, A, B, R(53) );
  P( B, C, D, E, A, R(54) );
  P( A, B, C, D, E, R(55) );
  P( E, A, B, C, D, R(56) );
  P( D, E, A, B, C, R(57) );
  P( C, D, E, A, B, R(58) );
  P( B, C, D, E, A, R(59) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

  P( A, B, C, D, E, R(60) );
  P( E, A, B, C, D, R(61) );
  P( D, E, A, B, C, R(62) );
  P( C, D, E, A, B, R(63) );
  P( B, C, D, E, A, R(64) );
  P( A, B, C, D, E, R(65) );
  P( E, A, B, C, D, R(66) );
  P( D, E, A, B, C, R(67) );
  P( C, D, E, A, B, R(68) );
  P( B, C, D, E, A, R(69) );
  P( A, B, C, D, E, R(70) );
  P( E, A, B, C, D, R(71) );
  P( D, E, A, B, C, R(72) );
  P( C, D, E, A, B, R(73) );
  P( B, C, D, E, A, R(74) );
  P( A, B, C, D, E, R(75) );
  P( E, A, B, C, D, R(76) );
  P( D, E, A, B, C, R(77) );
  P( C, D, E, A, B, R(78) );
  P( B, C, D, E, A, R(79) );

#undef K
#undef F

  ctx->Result[0] += A;
  ctx->Result[1] += B;
  ctx->Result[2] += C;
  ctx->Result[3] += D;
  ctx->Result[4] += E;
}


void sha1_update(Hash_CTX256 *ctx, uint8 *input, uint32 length )
{
  uint32 left, fill;

  if( ! length ) return;

  left = ctx->TotalLen[0] & 0x3F;
  fill = 64 - left;

  ctx->TotalLen[0] += length;
  ctx->TotalLen[0] &= 0xFFFFFFFF;

  if( ctx->TotalLen[0] < length )
   ctx->TotalLen[1]++;
 
  if( left && length >= fill )
  {
    memcpy1( (uint8 *) (ctx->TempBuf + left),
          (uint8 *) input, fill );
    sha1_process( ctx, ctx->TempBuf);
    length -= fill;
    input += fill;
    left = 0;
  }

  while( length >= 64 )
  {
    sha1_process( ctx, input );
    length -= 64;
    input += 64;
  }

  if( length )
  {
    memcpy1( (uint8 *) (ctx->TempBuf + left),
          (uint8 *) input, length );
  }
}

static uint8 sha1_padding[64] =
{
0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void sha1_finish( Hash_CTX256 *ctx, uint8 *digest)
{
  uint32 last, padn;
  uint32 high, low;
  uint8 msglen[8];

  high = ( ctx->TotalLen[0] >> 29 )
     | ( ctx->TotalLen[1] << 3 );
  low = ( ctx->TotalLen[0] << 3 );

  PUT_UINT32( high, msglen, 0 );
  PUT_UINT32( low, msglen, 4 );

  last = ctx->TotalLen[0] & 0x3F;
  padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

  sha1_update( ctx, sha1_padding, padn );
  sha1_update( ctx, msglen, 8 );

  PUT_UINT32( ctx->Result[0], digest, 0 );
  PUT_UINT32( ctx->Result[1], digest, 4 );
  PUT_UINT32( ctx->Result[2], digest, 8 );
  PUT_UINT32( ctx->Result[3], digest, 12 );
  PUT_UINT32( ctx->Result[4], digest, 16 );
}


void SHA512_F1(uint8 *pData,uint8 *Result)
{
	uint8 temp1[8]={0};
	uint8 temp2[8]={0};
	
	SHASHIFT(pData,36,0,temp1);
	SHASHIFT(pData,30,0,temp2);
	SHAXOR(temp1,temp2,temp1);

	SHASHIFT(pData,25,0,temp2);  
	
	SHAXOR(temp1,temp2,Result);
}

void SHA512_F2(uint8 *pData,uint8 *Result)
{
	uint8 temp1[8]={0};
	uint8 temp2[8]={0};
	SHASHIFT(pData,50,0,temp1);
	SHASHIFT(pData,46,0,temp2);
	SHAXOR(temp1,temp2,temp1);

	SHASHIFT(pData,23,0,temp2);  
	
	SHAXOR(temp1,temp2,Result);
}

void SHA512_F3(uint8 *pData,uint8 *Result)
{
	uint8 temp1[8]={0};
	uint8 temp2[8]={0};
	SHASHIFT(pData,63,0,temp1);
	SHASHIFT(pData,56,0,temp2);
	SHAXOR(temp1,temp2,temp1);

	SHASHIFT(pData,57,0,temp2);  //SHFR
	temp2[0] &= 0x01; //clear high 7 bit
	
	SHAXOR(temp1,temp2,Result);
}


void SHA512_F4(uint8 *pData,uint8 *Result)
{
	uint8 temp1[8]={0};
	uint8 temp2[8]={0};
	SHASHIFT(pData,45,0,temp1);
	SHASHIFT(pData,3,0,temp2);
	SHAXOR(temp1,temp2,temp1);

	SHASHIFT(pData,58,0,temp2);  //SHFR
	temp2[0] &= 0x03; //clear high 6 bit
	
	SHAXOR(temp1,temp2,Result);
}

void SHA512_SCR(uint8 *pData,uint8 i,uint8 *Result)
{
	uint8 temp1[8]={0};
	uint8 temp2[8]={0};

	SHA512_F4(pData+8*(i-2),temp1);
	SHAADD(temp1,pData+8*(i-7),temp2);
	SHA512_F3(pData+8*(i-15),temp1);
	SHAADD(temp1,temp2,temp2);
	SHAADD(temp2,pData+8*(i-16),Result);
}

void CH_function(uint8 *x,uint8 *y, uint8 *z,uint8 *Result)
{
	uint8 temp1[8]={0};
	uint8 temp2[8]={0};

	SHAAND(x,y,temp1);
	SHANOT(x,temp2);
	SHAAND(temp2,z,temp2);

	SHAXOR(temp1,temp2,Result);
}

void MAJ_function(uint8 *x,uint8 *y, uint8 *z,uint8 *Result)
{
	uint8 temp1[8]={0};
	uint8 temp2[8]={0};
		 
	SHAAND(x,y,temp1);
	SHAAND(x,z,temp2);
	SHAXOR(temp1,temp2,temp1);

	SHAAND(y,z,temp2);
	SHAXOR(temp1,temp2,Result);
}

void sha512_transf(Hash_CTX512 *ctx, uint8 *message,uint32 block_nb)
{
    uint8 temp1[8]={0};
	uint8 temp2[8]={0};
	uint8 w[80][8]={0};
    uint8 wv[8][8]={0};
    uint8 t1[8], t2[8];
    const uint8 *sub_block;
    const uint8 sha512_k[80][8] =
            {
			 0x42,0x8A,0x2F,0x98,0xD7,0x28,0xAE,0x22,
			 0x71,0x37,0x44,0x91,0x23,0xEF,0x65,0xCD,
			 0xB5,0xC0,0xFB,0xCF,0xEC,0x4D,0x3B,0x2F,
			 0xE9,0xB5,0xDB,0xA5,0x81,0x89,0xDB,0xBC,
			 0x39,0x56,0xC2,0x5B,0xF3,0x48,0xB5,0x38,
			 0x59,0xF1,0x11,0xF1,0xB6,0x05,0xD0,0x19,
			 0x92,0x3f,0x82,0xa4,0xaf,0x19,0x4f,0x9b,
			 0xab,0x1c,0x5e,0xd5,0xda,0x6d,0x81,0x18,
			 0xd8,0x07,0xaa,0x98,0xa3,0x03,0x02,0x42,  
			 0x12,0x83,0x5b,0x01,0x45,0x70,0x6f,0xbe,  //10
			 0x24,0x31,0x85,0xbe,0x4e,0xe4,0xb2,0x8c,
			 0x55,0x0c,0x7d,0xc3,0xd5,0xff,0xb4,0xe2,
			 0x72,0xbe,0x5d,0x74,0xf2,0x7b,0x89,0x6f,
			 0x80,0xde,0xb1,0xfe,0x3b,0x16,0x96,0xb1,
			 0x9b,0xdc,0x06,0xa7,0x25,0xc7,0x12,0x35,
			 0xc1,0x9b,0xf1,0x74,0xcf,0x69,0x26,0x94,
			 0xe4,0x9b,0x69,0xc1,0x9e,0xf1,0x4a,0xd2,
			 0xef,0xbe,0x47,0x86,0x38,0x4f,0x25,0xe3,
			 0x0f,0xc1,0x9d,0xc6,0x8b,0x8c,0xd5,0xb5,
			 0x24,0x0c,0xa1,0xcc,0x77,0xac,0x9c,0x65,	//20
			 0x2d,0xe9,0x2c,0x6f,0x59,0x2b,0x02,0x75,
			 0x4a,0x74,0x84,0xaa,0x6e,0xa6,0xe4,0x83,
			 0x5c,0xb0,0xa9,0xdc,0xbd,0x41,0xfb,0xd4,
			 0x76,0xf9,0x88,0xda,0x83,0x11,0x53,0xb5,
			 0x98,0x3e,0x51,0x52,0xee,0x66,0xdf,0xab,
			 0xa8,0x31,0xc6,0x6d,0x2d,0xb4,0x32,0x10,
			 0xb0,0x03,0x27,0xc8,0x98,0xfb,0x21,0x3f,
			 0xbf,0x59,0x7f,0xc7,0xbe,0xef,0x0e,0xe4,
			 0xc6,0xe0,0x0b,0xf3,0x3d,0xa8,0x8f,0xc2,
			 0xd5,0xa7,0x91,0x47,0x93,0x0a,0xa7,0x25,  //30
			 0x06,0xca,0x63,0x51,0xe0,0x03,0x82,0x6f,
			 0x14,0x29,0x29,0x67,0x0a,0x0e,0x6e,0x70,
			 0x27,0xb7,0x0a,0x85,0x46,0xd2,0x2f,0xfc,
			 0x2e,0x1b,0x21,0x38,0x5c,0x26,0xc9,0x26,
			 0x4d,0x2c,0x6d,0xfc,0x5a,0xc4,0x2a,0xed,
			 0x53,0x38,0x0d,0x13,0x9d,0x95,0xb3,0xdf,
			 0x65,0x0a,0x73,0x54,0x8b,0xaf,0x63,0xde,
			 0x76,0x6a,0x0a,0xbb,0x3c,0x77,0xb2,0xa8,
			 0x81,0xc2,0xc9,0x2e,0x47,0xed,0xae,0xe6,
			 0x92,0x72,0x2c,0x85,0x14,0x82,0x35,0x3b,  //40
			 0xa2,0xbf,0xe8,0xa1,0x4c,0xf1,0x03,0x64,
			 0xa8,0x1a,0x66,0x4b,0xbc,0x42,0x30,0x01,
			 0xc2,0x4b,0x8b,0x70,0xd0,0xf8,0x97,0x91,
			 0xc7,0x6c,0x51,0xa3,0x06,0x54,0xbe,0x30,
			 0xd1,0x92,0xe8,0x19,0xd6,0xef,0x52,0x18,
			 0xd6,0x99,0x06,0x24,0x55,0x65,0xa9,0x10,
			 0xf4,0x0e,0x35,0x85,0x57,0x71,0x20,0x2a,
			 0x10,0x6a,0xa0,0x70,0x32,0xbb,0xd1,0xb8,
			 0x19,0xa4,0xc1,0x16,0xb8,0xd2,0xd0,0xc8,
			 0x1e,0x37,0x6c,0x08,0x51,0x41,0xab,0x53,  //50
			 0x27,0x48,0x77,0x4c,0xdf,0x8e,0xeb,0x99,
			 0x34,0xb0,0xbc,0xb5,0xe1,0x9b,0x48,0xa8,
			 0x39,0x1c,0x0c,0xb3,0xc5,0xc9,0x5a,0x63,
			 0x4e,0xd8,0xaa,0x4a,0xe3,0x41,0x8a,0xcb,
			 0x5b,0x9c,0xca,0x4f,0x77,0x63,0xe3,0x73,
			 0x68,0x2e,0x6f,0xf3,0xd6,0xb2,0xb8,0xa3,
			 0x74,0x8f,0x82,0xee,0x5d,0xef,0xb2,0xfc,
			 0x78,0xa5,0x63,0x6f,0x43,0x17,0x2f,0x60,
			 0x84,0xc8,0x78,0x14,0xa1,0xf0,0xab,0x72,
			 0x8c,0xc7,0x02,0x08,0x1a,0x64,0x39,0xec,  //60
			 0x90,0xbe,0xff,0xfa,0x23,0x63,0x1e,0x28,
			 0xa4,0x50,0x6c,0xeb,0xde,0x82,0xbd,0xe9,
			 0xbe,0xf9,0xa3,0xf7,0xb2,0xc6,0x79,0x15,
			 0xc6,0x71,0x78,0xf2,0xe3,0x72,0x53,0x2b,
			 0xca,0x27,0x3e,0xce,0xea,0x26,0x61,0x9c,
			 0xd1,0x86,0xb8,0xc7,0x21,0xc0,0xc2,0x07,
			 0xea,0xda,0x7d,0xd6,0xcd,0xe0,0xeb,0x1e,
			 0xf5,0x7d,0x4f,0x7f,0xee,0x6e,0xd1,0x78,
			 0x06,0xf0,0x67,0xaa,0x72,0x17,0x6f,0xba,
			 0x0a,0x63,0x7d,0xc5,0xa2,0xc8,0x98,0xa6,	//70
			 0x11,0x3f,0x98,0x04,0xbe,0xf9,0x0d,0xae,
			 0x1b,0x71,0x0b,0x35,0x13,0x1c,0x47,0x1b,
			 0x28,0xdb,0x77,0xf5,0x23,0x04,0x7d,0x84,
			 0x32,0xca,0xab,0x7b,0x40,0xc7,0x24,0x93,
			 0x3c,0x9e,0xbe,0x0a,0x15,0xc9,0xbe,0xbc,
			 0x43,0x1d,0x67,0xc4,0x9c,0x10,0x0d,0x4c,
			 0x4c,0xc5,0xd4,0xbe,0xcb,0x3e,0x42,0xb6,
			 0x59,0x7f,0x29,0x9c,0xfc,0x65,0x7e,0x2a,
			 0x5f,0xcb,0x6f,0xab,0x3a,0xd6,0xfa,0xec,
			 0x6c,0x44,0x19,0x8c,0x4a,0x47,0x58,0x17,  //80
			 };

	int32 i, j,k;

    for (i = 0; i < (int32) block_nb; i++) 
	{
        sub_block = message + (i << 7);

		for(j=0;j<16;j++)
		{
			for(k=0;k<8;k++)
			w[j][k] =  sub_block[j*8+k];
			//memcpy1(&w[j][0],&sub_block[j*8],8);
		}

		 for(j=16;j<80;j++)
		 {
		 	SHA512_SCR(&w[0][0],j,&w[j][0]);
		 }

		for(j=0;j<8;j++)
		{
			for(k=0;k<8;k++)
			wv[j][k] = ctx->Result[j][k];
			//memcpy1(&wv[j][0],&(ctx->Result[j][0]),8);
		}

        for (j = 0; j < 80; j++) 
		{
            
			SHA512_F2(&wv[4][0],temp1);
			CH_function(&wv[4][0],&wv[5][0],&wv[6][0],temp2);

			SHAADD(temp1,temp2,temp1);
			SHAADD(temp1,&wv[7][0],temp2);
			SHAADD(temp2,(uint8 *)&sha512_k[j][0],temp1);
			SHAADD(temp1,&w[j][0],t1);
		   	
			SHA512_F1(&wv[0][0],temp1);
			MAJ_function(&wv[0][0],&wv[1][0],&wv[2][0],temp2);

			SHAADD(temp1,temp2,t2);

			for(k=0;k<8;k++)
			{
				wv[7][k] = wv[6][k];
				wv[6][k] = wv[5][k];
				wv[5][k] = wv[4][k];
			}
			//memcpy1(&wv[7][0],&wv[6][0],8);	
            //memcpy1(&wv[6][0],&wv[5][0],8);	
            //memcpy1(&wv[5][0],&wv[4][0],8);	
            
			SHAADD(&wv[3][0],t1,&wv[4][0]);
			
			for(k=0;k<8;k++) 
			{
			 	wv[3][k] = wv[2][k];
				wv[2][k] = wv[1][k];
				wv[1][k] = wv[0][k];
          	}
			//memcpy1(&wv[3][0],&wv[2][0],8);	
            //memcpy1(&wv[2][0],&wv[1][0],8);	
            //memcpy1(&wv[1][0],&wv[0][0],8);	
            
			SHAADD(t1,t2,&wv[0][0]);
        }

        for(j=0; j<8; j++)
		{
			SHAADD(&ctx->Result[j][0],&wv[j][0],&ctx->Result[j][0]);
		}
 	}
}

void sha512_update(Hash_CTX512 *ctx, uint8 *message,uint32 len)
{
    uint32 block_nb;
    uint32 new_len, rem_len, tmp_len;
    const uint8 *shifted_message;

    tmp_len = SHA512_BLOCK_SIZE - ctx->Len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy1(&ctx->TempBuf[ctx->Len], message, rem_len);

    if (ctx->Len + len < SHA512_BLOCK_SIZE) {
        ctx->Len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA512_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha512_transf(ctx, ctx->TempBuf, 1);
    sha512_transf(ctx, (uint8 *)shifted_message, block_nb);

    rem_len = new_len % SHA512_BLOCK_SIZE;

    memcpy1(ctx->TempBuf, &shifted_message[block_nb << 7],
           rem_len);

    ctx->Len = rem_len;
    ctx->TotalLen[0] += (block_nb + 1) << 7;
}

void sha512_final(Hash_CTX512 *ctx, uint8 *digest)
{
    uint32 block_nb;
    uint32 pm_len;
    uint32 len_b;

    int8 i,j;
    block_nb = 1 + ((SHA512_BLOCK_SIZE - 17)
                     < (ctx->Len % SHA512_BLOCK_SIZE));

    len_b = (ctx->TotalLen[0] + ctx->Len) << 3;
    pm_len = block_nb << 7;

    memset1(ctx->TempBuf + ctx->Len, 0, pm_len - ctx->Len);
    ctx->TempBuf[ctx->Len] = 0x80;
    UNPACK32(len_b, ctx->TempBuf + pm_len - 4);

    sha512_transf(ctx, ctx->TempBuf, block_nb);

    for(i = 0 ; i < 8; i++)
	{
		for(j = 0;j<8; j++)
		{
			digest[i*8+j] = ctx->Result[i][j];
		}
		//memcpy1(&digest[i*8],&(ctx->Result[i][0]),8);	
    }
}

void sha384_update(Hash_CTX512 *ctx, uint8 *message, uint32 len)
{
    uint32 block_nb;
    uint32 new_len, rem_len, tmp_len;
    const uint8 *shifted_message;

    tmp_len = SHA384_BLOCK_SIZE - ctx->Len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy1(&ctx->TempBuf[ctx->Len], message, rem_len);

    if (ctx->Len + len < SHA384_BLOCK_SIZE) {
        ctx->Len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA384_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha512_transf(ctx, ctx->TempBuf, 1);
    sha512_transf(ctx, (uint8 *)shifted_message, block_nb);

    rem_len = new_len % SHA384_BLOCK_SIZE;

    memcpy1(ctx->TempBuf, &shifted_message[block_nb << 7],
           rem_len);

    ctx->Len = rem_len;
    ctx->TotalLen[0] += (block_nb + 1) << 7;
}

void sha384_final(Hash_CTX512 *ctx, uint8 *digest)
{
    uint32 block_nb;
    uint32 pm_len;
    uint32 len_b;


    int8 i,j;


    block_nb = (1 + ((SHA384_BLOCK_SIZE - 17)
                     < (ctx->Len % SHA384_BLOCK_SIZE)));

    len_b = (ctx->TotalLen[0] + ctx->Len) << 3;
    pm_len = block_nb << 7;

    memset1(ctx->TempBuf + ctx->Len, 0, pm_len - ctx->Len);
    ctx->TempBuf[ctx->Len] = 0x80;
    UNPACK32(len_b, ctx->TempBuf + pm_len - 4);

    sha512_transf(ctx, ctx->TempBuf, block_nb);


    for(i = 0 ; i < 6; i++)
	{
		for(j = 0;j<8; j++)
		{
			digest[i*8+j] = ctx->Result[i][j];
		}
		//memcpy1(&digest[i*8],&(ctx->Result[i][0]),8);
    }
}

#if 0
void HashTest(void)
{
    Hash_CTX ctx;
	uint8 len;

	uint8 i;
	
	uint8 message[128]={0};
	uint8 digest[32];


	//#define TEST_SM3_2 1
	//#define TEST_SHA256_2 1
	//#define SHA_256 1

	#define TEST_SHA1_2 1
	#define SHA_1 1

	#if 0
	#if TESTSM31
	message[0] = 0x61;
	message[1] = 0x62;
	message[2] = 0x63;

	len  = 3;
	#endif

	#if TESTSM32
	for(i = 0; i<16; i++)
	{
		message[i*4] = 0x61;
		message[i*4+1] = 0x62;
		message[i*4+2] = 0x63;
		message[i*4+3] = 0x64;
		len =64;

	}
	#endif
	

	#if TEST_SHA256_1
	
	message[0] = 0x61;
	message[1] = 0x62;
	message[2] = 0x63;

	len  = 3;
	#endif


	#if TEST_SHA256_2
	
	for(i = 0; i<14; i++)
	{
		message[i*4] = 0x61+i;
		message[i*4+1] = 0x62+i;
		message[i*4+2] = 0x63+i;
		message[i*4+3] = 0x64+i;
		len = 56;

	}

	#endif
	
	#if TEST_SHA1_1
	
	message[0] = 0x61;
	message[1] = 0x62;
	message[2] = 0x63;

	len  = 3;
	#endif
    #endif

	#if TEST_SHA1_2
	for(i = 0; i<14; i++)
	{
		message[i*4] = 0x61+i;
		message[i*4+1] = 0x62+i;
		message[i*4+2] = 0x63+i;
		message[i*4+3] = 0x64+i;
		len = 56;

	}
	#endif

	#if SM3
    Hash_Init(&ctx,0);
    Hash_Update(&ctx, message, len);
    Hash_Final(&ctx, digest);
	#endif

	#if SHA_1
	Hash_Init(&ctx,1);
    Hash_Update(&ctx, message, len);
    Hash_Final(&ctx, digest);
	#endif

	
	#if SHA_256
	Hash_Init(&ctx,2);
    Hash_Update(&ctx, message, len);
    Hash_Final(&ctx, digest);
	#endif

	
}
#endif
