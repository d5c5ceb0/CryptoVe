#ifndef _SHA_H_
#define _SHA_H_


/*
**结 构 体: Hash_CTX256
**功能说明: 定义HASH运算的上下文环境，缓存中间结果。运算前需要初始化。
**备    注:   
*/
typedef struct //Hash_CTX256
{
     unsigned char      TempBuf[128];          //临时数据
     unsigned int     Result[8];             //运算结果
     unsigned int     TotalLen[2];           //输入数据总长度 byte
     unsigned char      Len;                   //最后一块长度 byte
     unsigned char      AlgFlag;               //HASH类型标志

} Hash_CTX256;

typedef struct //Hash_CTX512
{
    unsigned char      TempBuf[256];        //临时数据//考虑到两组的情况 *2
    unsigned char      Result[8][8];        //运算结果
    unsigned int	   TotalLen[2];         //输入数据总长度  byte
    unsigned char      Len;                 //最后一块长度 byte
    unsigned char      AlgFlag;             //hash模式选择

} Hash_CTX512;

/*
**函数名称: Hash_Init
**功能说明: 初始化Hash函数上下文，每次运算前必须调用。
**参数说明: HashCtx: 指向HASH上下文结构体对象的指针。
**          Hash_mode: HASH模式选择，包括SHA-1，SHA-224, SHA-256
**                     1 - SHA-1, 2 - SHA-244, 3 - SHA-256
**返 回 值: 无
**备    注: 无 
*/
extern unsigned char Hash_Init(Hash_CTX256 *HashCtx, unsigned char Hash_mode);


/*
**函数名称: Hash_Update
**功能说明: 对输入的消息进行HASH运算，支持分包输入，支持可变长度。
**参数说明: HashCtx: 指向HASH上下文结构体对象的指针，使用前需要初始化。
**          Hash_DataIn: 指向消息地址的指针。
**          InLen: 输入消息的字节长度。
**返 回 值: 无
**备    注: 无  
*/
extern unsigned char Hash_Update(Hash_CTX256 *HashCtx, unsigned char *Hash_DataIn, unsigned int InLen);


/*
**函数名称: Hash_Final
**功能说明: 对所有消息运算完成后，调用本函数得到杂凑值。
**参数说明: HashCtx: 指向HASH上下文结构体对象的指针。
**          Hash_DataOut: 指向杂凑值接收地址的指针，模式不同，需求空间不同。
**返 回 值: 无
**备    注: 无 
*/
extern unsigned char Hash_Final(Hash_CTX256 *HashCtx, unsigned char *Hash_DataOut);




/*
**函数名称: Hash_Final
**功能说明: 对所有消息运算完成后，调用本函数得到杂凑值。
**参数说明: HashCtx: 指向HASH上下文结构体对象的指针。
**          Hash_DataOut: 指向杂凑值接收地址的指针，模式不同，需求空间不同。
**返 回 值: 无
**备    注: 无 
*/
extern unsigned char Hash_Final(Hash_CTX256 *HashCtx, unsigned char *Hash_DataOut);


/*
**函数名称: Hash_Init1
**功能说明: 初始化Hash函数上下文，每次运算前必须调用。
**参数说明: HashCtx: 指向HASH上下文结构体对象的指针。
**          Hash_mode: HASH模式选择，包括SHA-384，SHA-512
**                     1 - SHA-1, 2 - SHA-244, 3 - SHA-256
**返 回 值: 无
**备    注: 无 
*/
extern unsigned char Hash_Init1(Hash_CTX512 *HashCtx, unsigned char Hash_mode);

/*
**函数名称: Hash_Update1
**功能说明: 对输入的消息进行HASH运算，支持分包输入，支持可变长度。
**参数说明: HashCtx: 指向HASH上下文结构体对象的指针，使用前需要初始化。
**          Hash_DataIn: 指向消息地址的指针。
**          InLen: 输入消息的字节长度。
**返 回 值: 无
**备    注: 无  
*/
extern unsigned char Hash_Update1(Hash_CTX512 *HashCtx, unsigned char *Hash_DataIn, unsigned int InLen);

/*
**函数名称: Hash_Final1
**功能说明: 对所有消息运算完成后，调用本函数得到杂凑值。
**参数说明: HashCtx: 指向HASH上下文结构体对象的指针。
**          Hash_DataOut: 指向杂凑值接收地址的指针，模式不同，需求空间不同。
**返 回 值: 无
**备    注: 无 
*/
extern unsigned char Hash_Final1(Hash_CTX512 *HashCtx, unsigned char *Hash_DataOut);

#endif


