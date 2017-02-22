#ifndef _SHA_H_
#define _SHA_H_


typedef struct //Hash_CTX256
{
     unsigned char      TempBuf[128];     
     unsigned int     Result[8];         
     unsigned int     TotalLen[2];      
     unsigned char      Len;           
     unsigned char      AlgFlag;            

} Hash_CTX256;

typedef struct //Hash_CTX512
{
    unsigned char      TempBuf[256];     
    unsigned char      Result[8][8];    
    unsigned int	   TotalLen[2];    
    unsigned char      Len;           
    unsigned char      AlgFlag;      

} Hash_CTX512;

extern unsigned char Hash_Init(Hash_CTX256 *HashCtx, unsigned char Hash_mode);

extern unsigned char Hash_Update(Hash_CTX256 *HashCtx, unsigned char *Hash_DataIn, unsigned int InLen);

extern unsigned char Hash_Final(Hash_CTX256 *HashCtx, unsigned char *Hash_DataOut);

extern unsigned char Hash_Init1(Hash_CTX512 *HashCtx, unsigned char Hash_mode);

extern unsigned char Hash_Update1(Hash_CTX512 *HashCtx, unsigned char *Hash_DataIn, unsigned int InLen);

extern unsigned char Hash_Final1(Hash_CTX512 *HashCtx, unsigned char *Hash_DataOut);

#endif


