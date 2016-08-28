/**********************************************************************
  Copyright (C), 2013-2014, SHHIC Co., Ltd. All Right Reserved.

  文件名: sm3.h
  作  者: 张伟    版本: V1.0.0    日期: 2014-02-20
  
  描  述: SM3算法头文件
  依  赖: 无
  历  史：
          1. 张伟 2014-02-20 V1.0.0
            (1) 初始版本。
  
***********************************************************************/

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


