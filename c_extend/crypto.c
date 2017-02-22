/* 
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */

#include <string.h>
#include <tcl.h>
#include "math.h"
#include "aes.h"
#include "des.h"
#include "sm4.h"
#include "md5.h"
#include "sm3.h"
#include "sha.h"

int DLLEXPORT Crypto_Init(Tcl_Interp* interp);

//#define FORWINDOWS
#ifdef FORWINDOWS
#pragma comment(lib,"tcl85.lib")
#endif

#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)<(b)?(b):(a))

int HexStrToByteArr(unsigned char out[],const char *in, unsigned int inStrLen)
{
	unsigned int i;

	if(inStrLen%2)
		return 0;

	for(i = 0; i < inStrLen/2; i++)
    {
        char cHigh = in[i*2];
        char cLow = in[i*2+1];

        if( ( ( cHigh >= 0x30 ) && (cHigh <= 0x39 ) ) || ( ( cHigh >= 0x41) && ( cHigh <= 0x46 ) ) ||  ( ( cHigh >= 0x61) && ( cHigh <= 0x66 ) ))
        {
            cHigh = ( cHigh < 0x40 )? ( cHigh - 0x30 ):( (cHigh<0x50)?(cHigh - 0x37):(cHigh - 0x57) );
        }
        else
        {
            return 0;
        }

        if( ( ( cLow >= 0x30 ) && ( cLow <= 0x39 ) ) || ( ( cLow >= 0x41 ) && ( cLow <= 0x46 ) ) || ( ( cLow >= 0x61) && ( cLow <= 0x66 ) ))
        {
            cLow = ( cLow < 0x40 )? ( cLow - 0x30 ):((cLow<0x50)?(cLow - 0x37):(cLow - 0x57));
        }
        else
        {
            return 0;
        }

        out[i] =  (cHigh << 4) + cLow;
    }

	return 1;
}


int ByteArrToHexStr(char out[], const unsigned char in[], unsigned int inBLen)
{
	unsigned int i;

	for(i=0; i<inBLen; i++)
		sprintf(&out[2*i],"%02x", in[i]);

	return 1;
}

/**************************************************************
name:VersionCmd
description:crypto lib version
usage:version
**************************************************************/
static int
VersionCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	Tcl_SetObjResult(interp, Tcl_NewStringObj("crypto version: 1.0.0", -1));
	return TCL_OK;
}


/**************************************************************
name:AddCmd
description:r = a + b
usage:add a b
**************************************************************/
int AddCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 3)
	{
		Tcl_SetResult(interp,"Error: [add a b] The number of arguments need be 2.",TCL_VOLATILE);
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [add a b] The length of argument a must be even",TCL_VOLATILE);
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [add a b] The length of argument b must be even",TCL_VOLATILE);
		return TCL_ERROR;
	}

	Add(inPara, &outPara[1]);

	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}


/**************************************************************
name:SubCmd
description:r = a - b
usage:sub a b
**************************************************************/
int SubCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	if( objc != 3)
	{
		Tcl_SetResult( interp,"Error: [sub a b] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [sub a b] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [sub a b] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	Sub(inPara, &outPara[1]);
	if (outPara[1] == '-') {
		if (strlen(&outPara[1])%2) {
			//-01
			Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
		} else {
			//-1
			outPara[0] = '-';
			outPara[1] = '0';
			Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
		}
	} else {
		if (strlen(&outPara[1])%2) {
			//1
			outPara[0] = '0';
			Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
		} else {
			//01
			Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
		}
	}

	return TCL_OK;
}


/**************************************************************
name:MulCmd
description:r = a * b
usage:mul a b
**************************************************************/
int MulCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if(objc != 3)
	{
		Tcl_SetResult( interp,"Error: [mul a b] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [mul a b] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [mul a b] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	Mul(inPara, &outPara[1]);

	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}

/**************************************************************
name:DivCmd
description:r = a / b
usage:div a b
**************************************************************/
int DivCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if(objc != 3)
	{
		Tcl_SetResult( interp,"Error: [div a b] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [div a b] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [div a b] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	Div(inPara, &outPara[1]);

	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}

/**************************************************************
name:RemCmd
description:r = a % b
usage:rem a b
**************************************************************/
int RemCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 3)
	{
		Tcl_SetResult( interp,"Error: [rem a b] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [rem a b] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [rem a b] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	Rem(inPara, &outPara[1]);

	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}

/**************************************************************
name:CmpCmd
description: compare
usage:cmp a b
**************************************************************/
int CmpCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 3)
	{
		Tcl_SetResult( interp,"Error: [cmp a b] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [cmp a b] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [cmp a b] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	Cmp(inPara, outPara);
	Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE );

	return TCL_OK;
}


/**************************************************************
name:OrrCmd
description: bit or
usage:orr a b
**************************************************************/
int OrrCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *para_a, *para_b;
	int ParaALen, ParaBLen, minlen, maxlen;
	unsigned char ParaA[2048]={0}, ParaB[2048]={0};
	unsigned char out[2048];
	char output[4097];
	int i;

	Crypto_Init(interp);
	
	if( objc != 3)
	{
		Tcl_SetResult( interp,"Error: [orr a b] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	para_a = Tcl_GetStringFromObj(objv[1], &ParaALen);
	if(ParaALen%2)
	{
		Tcl_SetResult( interp,"Error: [orr a b] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	para_b = Tcl_GetStringFromObj(objv[2], &ParaBLen);
	if(ParaBLen%2)
	{
		Tcl_SetResult( interp,"Error: [orr a b] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	minlen = min(ParaALen, ParaBLen);
	maxlen = max(ParaALen, ParaBLen);
 
	HexStrToByteArr(&ParaA[(ParaBLen-minlen)/2], para_a, ParaALen);
	HexStrToByteArr(&ParaB[(ParaALen-minlen)/2], para_b, ParaBLen);
	

	for(i=0; i<(maxlen/2); i++)
	{
		out[i] = ParaA[i] | ParaB[i];
	}

	ByteArrToHexStr(output, out, maxlen/2);

	Tcl_SetResult( interp,output,TCL_VOLATILE );

	return TCL_OK;
}

/**************************************************************
name:AndCmd
description: 
usage:and a b
**************************************************************/
int AndCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *para_a, *para_b;
	int ParaALen, ParaBLen, minlen, maxlen;
	unsigned char ParaA[2048]={0}, ParaB[2048]={0};
	unsigned char out[2048];
	char output[4097];
	int i;

	Crypto_Init(interp);
	
	if( objc != 3)
	{
		Tcl_SetResult( interp,"Error: [and a b] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	para_a = Tcl_GetStringFromObj(objv[1], &ParaALen);
	if(ParaALen%2)
	{
		Tcl_SetResult( interp,"Error: [and a b] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	para_b = Tcl_GetStringFromObj(objv[2], &ParaBLen);
	if(ParaBLen%2)
	{
		Tcl_SetResult( interp,"Error: [and a b] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	minlen = min(ParaALen, ParaBLen);
	maxlen = max(ParaALen, ParaBLen);
 
	HexStrToByteArr(&ParaA[(ParaBLen-minlen)/2], para_a, ParaALen);
	HexStrToByteArr(&ParaB[(ParaALen-minlen)/2], para_b, ParaBLen);
	

	for(i=0; i<(maxlen/2); i++)
	{
		out[i] = ParaA[i] & ParaB[i];
	}

	ByteArrToHexStr(output, out, maxlen/2);

	Tcl_SetResult( interp,output,TCL_VOLATILE );

	return TCL_OK;
}

/**************************************************************
name:NotCmd
description: 
usage: not a
**************************************************************/
int NotCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *para_a;
	int ParaALen;
	unsigned char ParaA[2048]={0};
	unsigned char out[2048];
	char output[4097];
	int i;

	Crypto_Init(interp);
	
	if( objc != 2)
	{
		Tcl_SetResult( interp,"Error: [not a] The number of arguments need be 1.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	para_a = Tcl_GetStringFromObj(objv[1], &ParaALen);
	if(ParaALen%2)
	{
		Tcl_SetResult( interp,"Error: [not a] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	HexStrToByteArr(ParaA, para_a, ParaALen);
	

	for(i=0; i<(ParaALen/2); i++)
	{
		out[i] = ~ParaA[i];
	}

	ByteArrToHexStr(output, out, ParaALen/2);

	Tcl_SetResult( interp,output,TCL_VOLATILE );

	return TCL_OK;
}


/**************************************************************
name:XorCmd
description: 
usage: xor a b
**************************************************************/
int XorCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *para_a, *para_b;
	int ParaALen, ParaBLen, minlen, maxlen;
	unsigned char ParaA[2048]={0}, ParaB[2048]={0};
	unsigned char out[2048];
	char output[4097];
	int i;

	Crypto_Init(interp);
	
	if( objc != 3)
	{
		Tcl_SetResult( interp,"Error: [xor a b] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	para_a = Tcl_GetStringFromObj(objv[1], &ParaALen);
	if(ParaALen%2)
	{
		Tcl_SetResult( interp,"Error: [xor a b] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	para_b = Tcl_GetStringFromObj(objv[2], &ParaBLen);
	if(ParaBLen%2)
	{
		Tcl_SetResult( interp,"Error: [xor a b] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	minlen = min(ParaALen, ParaBLen);
	maxlen = max(ParaALen, ParaBLen);
 
	HexStrToByteArr(&ParaA[(ParaBLen-minlen)/2], para_a, ParaALen);
	HexStrToByteArr(&ParaB[(ParaALen-minlen)/2], para_b, ParaBLen);
	

	for(i=0; i<(maxlen/2); i++)
	{
		out[i] = ParaA[i] ^ ParaB[i];
	}

	ByteArrToHexStr(output, out, maxlen/2);

	Tcl_SetResult( interp,output,TCL_VOLATILE );

	return TCL_OK;
}


int SftCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[3];
	char outPara[4097];
	int ModParaLen;
	int tmp;
	
	Crypto_Init(interp);
	
	if( objc != 4)
	{
		Tcl_SetResult( interp,"Error: [sft mode x n] The number of arguments need be 3.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if((inPara[0][0] != 'R')&&(inPara[0][0] != 'r')&&(inPara[0][0] != 'L')&&(inPara[0][0] != 'l'))
	{
		Tcl_SetResult( interp,"Error: [sft mode x n] The arg mode must be r, R, l or L.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [sft mode x n] The length of argument x must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

    if(Tcl_GetIntFromObj(interp, objv[3], &tmp) != TCL_OK) 
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[sft mode x n] The arg n should be an interger.", -1));
        return TCL_ERROR;
    }
	inPara[2] = Tcl_GetStringFromObj(objv[3], &ModParaLen);

	Sft(inPara, &outPara[1]);

	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}


int GcdCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if(objc != 3)
	{
		Tcl_SetResult( interp,"Error: [gcd a b] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [gcd a b] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [gcd a b] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	Gcd(inPara, &outPara[1]);

	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}


int IsPrimeCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 2)
	{
		Tcl_SetResult( interp,"Error: [isprime a] The number of arguments need be 1.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [isprime a] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	IsPrime(inPara, outPara);
	Tcl_SetResult(interp,(char *)outPara, TCL_VOLATILE);

	return TCL_OK;
}


int GenPrimeCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if(objc != 2)
	{
		Tcl_SetResult(interp,"Error: [genprime num] The number of arguments need be 1.",TCL_VOLATILE);
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);

	GenPrime(inPara, &outPara[1]);
	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}


int ModAddCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[3];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 4)
	{
		Tcl_SetResult( interp,"Error: [modadd a b n] The number of arguments need be 3.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modadd a b n] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modadd a b n] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[2] = Tcl_GetStringFromObj(objv[3], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modadd a b n] The length of argument n must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	if(ModAdd(inPara, &outPara[1]))
	{
		Tcl_SetResult( interp,(char *)&outPara[1],TCL_VOLATILE );
		return TCL_ERROR;
	}

	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}


int ModSubCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[3];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 4)
	{
		Tcl_SetResult( interp,"Error: [modsub a b n] The number of arguments need be 3.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modsub a b n] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modsub a b n] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[2] = Tcl_GetStringFromObj(objv[3], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modsub a b n] The length of argument n must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	if(ModSub(inPara, &outPara[1]))
	{
		Tcl_SetResult( interp,(char *)&outPara[1],TCL_VOLATILE );
		return TCL_ERROR;
	}
	
	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}

int ModMulCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[3];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 4)
	{
		Tcl_SetResult( interp,"Error: [modmul a b n] The number of arguments need be 3.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modmul a b n] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modmul a b n] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[2] = Tcl_GetStringFromObj(objv[3], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modmul a b n] The length of argument c must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	if(ModMul(inPara, &outPara[1]))
	{
		Tcl_SetResult( interp,(char *)&outPara[1],TCL_VOLATILE );
		return TCL_ERROR;
	}
	
	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}

int ModInvCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 3)
	{
		Tcl_SetResult( interp,"Error: [modinv a n] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modinv a n] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modinv a n] The length of argument n must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	if(ModInv(inPara, &outPara[1]))
	{
		Tcl_SetResult( interp,(char *)&outPara[1],TCL_VOLATILE );
		return TCL_ERROR;
	}

	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}


int ModExpCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[3];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 4)
	{
		Tcl_SetResult( interp,"Error: [modexp a b n] The number of arguments need be 3.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modexp a b n] The length of argument a must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modexp a b n] The length of argument b must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[2] = Tcl_GetStringFromObj(objv[3], &ModParaLen);
	if(ModParaLen%2)
	{
		Tcl_SetResult( interp,"Error: [modexp a b n] The length of argument n must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	if(ModExp(inPara, &outPara[1]))
	{
		Tcl_SetResult( interp,(char *)&outPara[1],TCL_VOLATILE );
		return TCL_ERROR;
	}

	if (strlen(&outPara[1])%2) {
		outPara[0] = '0';
		Tcl_SetResult(interp, (char *)outPara, TCL_VOLATILE);
	} else {
		Tcl_SetResult(interp, (char *)&outPara[1], TCL_VOLATILE);
	}

	return TCL_OK;
}

int PointInCurveCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[5];
	char ecPara[5][4096];
	char outPara[4097];
	int EcParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 3)
	{
		Tcl_SetResult( interp,"Error: [ispoint (Px||Py) (p||a||b)] The number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &EcParaLen);
	if(EcParaLen % (2*2))
	{
		Tcl_SetResult( interp,"Error: [ispoint (Px||Py) (p||a||b)] The length of argument (Px||Py) must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}
	memcpy(ecPara[0],inPara[0], EcParaLen/2);
	memcpy(ecPara[1],inPara[0]+EcParaLen/2, EcParaLen/2);
	ecPara[0][EcParaLen/2] = '\0';
	ecPara[1][EcParaLen/2] = '\0';

	inPara[1] = Tcl_GetStringFromObj(objv[2], &EcParaLen);
	if(EcParaLen % (2*3))
	{
		Tcl_SetResult( interp,"Error: [ispoint (Px||Py) (p||a||b)] The length of argument (p||a||b) must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	memcpy(ecPara[2],inPara[1], EcParaLen/3);
	memcpy(ecPara[3],inPara[1]+EcParaLen/3, EcParaLen/3);
	memcpy(ecPara[4],inPara[1]+EcParaLen/3*2, EcParaLen/3);
	ecPara[2][EcParaLen/3] = '\0';
	ecPara[3][EcParaLen/3] = '\0';
	ecPara[4][EcParaLen/3] = '\0';

	inPara[0] = ecPara[0];
	inPara[1] = ecPara[1];
	inPara[2] = ecPara[2];
	inPara[3] = ecPara[3];
	inPara[4] = ecPara[4];

	if(IsPointInCurve(inPara, outPara))
	{
		Tcl_SetResult( interp,(char *)outPara,TCL_VOLATILE );
		return TCL_ERROR;
	}

	Tcl_SetResult( interp,(char *)outPara,TCL_VOLATILE );
	return TCL_OK;
}


int PointAddCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[7];
	char ecPara[7][4096];
	char outPara[4097];
	int EcParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 4)
	{
		Tcl_SetResult( interp,"Error: [padd (Pax||Pay) (Pbx||Pby) (P||A||B)] The number of arguments need be 3.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &EcParaLen);
	if(EcParaLen % (2*2))
	{
		Tcl_SetResult( interp,"Error: [padd (Pax||Pay) (Pbx||Pby) (P||A||B)] The length of argument (Pax||Pay) must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}
	memcpy(ecPara[0],inPara[0], EcParaLen/2);
	memcpy(ecPara[1],inPara[0]+EcParaLen/2, EcParaLen/2);
	ecPara[0][EcParaLen/2] = '\0';
	ecPara[1][EcParaLen/2] = '\0';

	inPara[1] = Tcl_GetStringFromObj(objv[2], &EcParaLen);
	if(EcParaLen % (2*2))
	{
		Tcl_SetResult( interp,"Error: [padd (Pax||Pay) (Pbx||Pby) (P||A||B)] The length of argument (Pbx||Pby) must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}
	memcpy(ecPara[2],inPara[1], EcParaLen/2);
	memcpy(ecPara[3],inPara[1]+EcParaLen/2, EcParaLen/2);
	ecPara[2][EcParaLen/2] = '\0';
	ecPara[3][EcParaLen/2] = '\0';

	inPara[2] = Tcl_GetStringFromObj(objv[3], &EcParaLen);
	if(EcParaLen % (2*3))
	{
		Tcl_SetResult( interp,"Error: [padd (Pax||Pay) (Pbx||Pby) (P||A||B)] The length of argument (P||A||B) must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	memcpy(ecPara[4],inPara[2], EcParaLen/3);
	memcpy(ecPara[5],inPara[2]+EcParaLen/3, EcParaLen/3);
	memcpy(ecPara[6],inPara[2]+EcParaLen/3*2, EcParaLen/3);
	ecPara[4][EcParaLen/3] = '\0';
	ecPara[5][EcParaLen/3] = '\0';
	ecPara[6][EcParaLen/3] = '\0';

	inPara[0] = ecPara[0];
	inPara[1] = ecPara[1];
	inPara[2] = ecPara[2];
	inPara[3] = ecPara[3];
	inPara[4] = ecPara[4];
	inPara[5] = ecPara[5];
	inPara[6] = ecPara[6];

	if(EcPointAdd(inPara, outPara))
	{
		Tcl_SetResult( interp,(char *)outPara,TCL_VOLATILE );
		return TCL_ERROR;
	}

	Tcl_SetResult( interp,(char *)outPara,TCL_VOLATILE );
	return TCL_OK;
}

int PointMulCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[6];
	char ecPara[6][4096];
	char outPara[4097];
	int EcParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 4)
	{
		Tcl_SetResult( interp,"Error: [pmul k (Px||Py) (p||a||b)] The number of arguments need be 3.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &EcParaLen);
	if(EcParaLen % 2)
	{
		Tcl_SetResult( interp,"Error: [pmul k (Px||Py) (p||a||b)] The length of argument k must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}
	strcpy(ecPara[0],inPara[0]);

	inPara[1] = Tcl_GetStringFromObj(objv[2], &EcParaLen);
	if(EcParaLen % (2*2))
	{
		Tcl_SetResult( interp,"Error: [pmul k (Px||Py) (p||a||b)] The length of argument (Px||Py) must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}
	memcpy(ecPara[1],inPara[1], EcParaLen/2);
	memcpy(ecPara[2],inPara[1]+EcParaLen/2, EcParaLen/2);
	ecPara[1][EcParaLen/2] = '\0';
	ecPara[2][EcParaLen/2] = '\0';

	inPara[2] = Tcl_GetStringFromObj(objv[3], &EcParaLen);
	if(EcParaLen % (2*3))
	{
		Tcl_SetResult( interp,"Error: [pmul k (Px||Py) (p||a||b)] The length of argument (p||a||b) must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	memcpy(ecPara[3],inPara[2], EcParaLen/3);
	memcpy(ecPara[4],inPara[2]+EcParaLen/3, EcParaLen/3);
	memcpy(ecPara[5],inPara[2]+EcParaLen/3*2, EcParaLen/3);
	ecPara[3][EcParaLen/3] = '\0';
	ecPara[4][EcParaLen/3] = '\0';
	ecPara[5][EcParaLen/3] = '\0';

	inPara[0] = ecPara[0];
	inPara[1] = ecPara[1];
	inPara[2] = ecPara[2];
	inPara[3] = ecPara[3];
	inPara[4] = ecPara[4];
	inPara[5] = ecPara[5];


	if(EcPointMul(inPara, outPara))
	{
		Tcl_SetResult( interp,(char *)outPara,TCL_VOLATILE );
		return TCL_ERROR;
	}

	Tcl_SetResult( interp,(char *)outPara,TCL_VOLATILE );
	return TCL_OK;
}

int EcMultPointMulCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[9];
	char ecPara[9][4096];
	char outPara[4097];
	int EcParaLen;
	
	Crypto_Init(interp);
	
	if( objc != 6)
	{
		Tcl_SetResult( interp,"Error: [mpmul k (Px||Py) k2 (P2x||P2y) (p||a||b)] The number of arguments need be 5.",TCL_VOLATILE );
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &EcParaLen);
	if(EcParaLen % 2)
	{
		Tcl_SetResult( interp,"Error: [mpmul k (Px||Py) k2 (P2x||P2y) (p||a||b)] The length of argument k must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}
	strcpy(ecPara[0],inPara[0]);

	inPara[1] = Tcl_GetStringFromObj(objv[2], &EcParaLen);
	if(EcParaLen % (2*2))
	{
		Tcl_SetResult( interp,"Error: [mpmul k (Px||Py) k2 (P2x||P2y) (p||a||b)] The length of argument (Px||Py) must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}
	memcpy(ecPara[1],inPara[1], EcParaLen/2);
	memcpy(ecPara[2],inPara[1]+EcParaLen/2, EcParaLen/2);
	ecPara[1][EcParaLen/2] = '\0';
	ecPara[2][EcParaLen/2] = '\0';

	inPara[2] = Tcl_GetStringFromObj(objv[3], &EcParaLen);
	if(EcParaLen % 2)
	{
		Tcl_SetResult( interp,"Error: [mpmul k (Px||Py) k2 (P2x||P2y) (p||a||b)] The length of argument k2 must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}
	strcpy(ecPara[3],inPara[2]);

	inPara[3] = Tcl_GetStringFromObj(objv[4], &EcParaLen);
	if(EcParaLen % (2*2))
	{
		Tcl_SetResult( interp,"Error: [mpmul k (Px||Py) k2 (P2x||P2y) (p||a||b)] The length of argument (Pax||Pay) must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}
	memcpy(ecPara[4],inPara[3], EcParaLen/2);
	memcpy(ecPara[5],inPara[3]+EcParaLen/2, EcParaLen/2);
	ecPara[4][EcParaLen/2] = '\0';
	ecPara[5][EcParaLen/2] = '\0';


	inPara[4] = Tcl_GetStringFromObj(objv[5], &EcParaLen);
	if(EcParaLen % (2*3))
	{
		Tcl_SetResult( interp,"Error: [mpmul k (Px||Py) k2 (P2x||P2y) (p||a||b)] The length of argument (p||a||b) must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

	memcpy(ecPara[6],inPara[4], EcParaLen/3);
	memcpy(ecPara[7],inPara[4]+EcParaLen/3, EcParaLen/3);
	memcpy(ecPara[8],inPara[4]+EcParaLen/3*2, EcParaLen/3);
	ecPara[6][EcParaLen/3] = '\0';
	ecPara[7][EcParaLen/3] = '\0';
	ecPara[8][EcParaLen/3] = '\0';

	inPara[0] = ecPara[0];
	inPara[1] = ecPara[1];
	inPara[2] = ecPara[2];
	inPara[3] = ecPara[3];
	inPara[4] = ecPara[4];
	inPara[5] = ecPara[5];
	inPara[6] = ecPara[6];
	inPara[7] = ecPara[7];
	inPara[8] = ecPara[8];

	if(EcMultPointMul(inPara, outPara))
	{
		Tcl_SetResult( interp,(char *)outPara,TCL_VOLATILE );
		return TCL_ERROR;
	}

	Tcl_SetResult( interp,(char *)outPara,TCL_VOLATILE );
	return TCL_OK;
}


int RngCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *inPara[2];
	char outPara[4097];
	int ModParaLen;
	
	Crypto_Init(interp);
	
	if( (objc < 2) ||(objc >3))
	{
		Tcl_SetResult(interp,"Usage: rng len ?str?.\nThe number of arguments need be 1 or 2.",TCL_VOLATILE);
		return TCL_ERROR;
	}

	inPara[0] = Tcl_GetStringFromObj(objv[1], &ModParaLen);

	if(objc != 2)
	{
		inPara[1] = Tcl_GetStringFromObj(objv[2], &ModParaLen);
	}
	else
	{
		inPara[1] = "0123456789abcdef";
	}
	
	Rng(inPara, outPara);
	Tcl_SetResult( interp,(char *)outPara,TCL_VOLATILE );

	return TCL_OK;
}


int AESEcbCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *in_str, *key_str;
    unsigned char key[32], in[0x200];
	char tmp[0x401];
	unsigned char tmp2[0x401];
    int mlen, i, mode, dlen;
	aes_context ctx;

	Crypto_Init(interp);

    if(objc != 4)
    {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[aesecb mode key data] The number of args must be 3.", -1));
        return TCL_ERROR;
    }

    if(Tcl_GetIntFromObj(interp, objv[1], &mode) != TCL_OK) 
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[aesecb mode key data] The arg mode should be an interger(00-encrypt, 01-decrypt).", -1));
        return TCL_ERROR;
    }
	if((mode != 0) &&(mode != 1))
	{
		Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[aesecb mode key data] The arg mode should be an interger(00-encrypt, 01-decrypt).", -1));
        return TCL_ERROR;
	}

    key_str = Tcl_GetStringFromObj(objv[2], &mlen);
	if((mlen!=16*2)&&(mlen!=24*2)&&(mlen!=32*2))
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[aesecb mode key data] The length of arg key should be 16, 24 or 32 Bytes.", -1));
        return TCL_ERROR;
    }

    in_str = Tcl_GetStringFromObj(objv[3], &dlen);
    if(dlen != 16*2)
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[aesecb mode key data] The length of arg data should be 16 Bytes.", -1));
        return TCL_ERROR;
    }

	HexStrToByteArr(key, key_str, mlen);
	HexStrToByteArr(in, in_str, dlen);

	aes_set_key(&ctx, key, mlen/2*8 );
	if(mode == 0)
		aes_encrypt(&ctx, in, tmp2 );
	else 
		aes_decrypt(&ctx, in, tmp2 );

    for(i=0; i<dlen/2; i++)
        sprintf(tmp+2*i, "%02x", tmp2[i]);

    Tcl_SetObjResult(interp, Tcl_NewStringObj(tmp, -1));

    return TCL_OK;
}


int DESEcbCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *in_str, *key_str;
    unsigned char key[32], in[0x200];
	char tmp[0x401];
    int mlen, i, mode, dlen;

	Crypto_Init(interp);

    if(objc != 4)
    {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[desecb mode key data] The number of args must be 3.", -1));
        return TCL_ERROR;
    }

    if(Tcl_GetIntFromObj(interp, objv[1], &mode) != TCL_OK) 
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[desecb mode key data] The arg mode should be an interger(00-encrypt, 01-decrypt).", -1));
        return TCL_ERROR;
    }
	if((mode != 0) &&(mode != 1))
	{
		Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[desecb mode key data] The arg mode should be an interger(00-encrypt, 01-decrypt).", -1));
        return TCL_ERROR;
	}

    key_str = Tcl_GetStringFromObj(objv[2], &mlen);
    if(mlen != 16)
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[desecb mode key data] The length of arg key should be 8 Bytes.", -1));
        return TCL_ERROR;
    }

    in_str = Tcl_GetStringFromObj(objv[3], &dlen);
    if(dlen%16)
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error:[desecb mode key data] The length of arg data should be multiple of 8 Bytes.", -1));
        return TCL_ERROR;
    }

	HexStrToByteArr(key, key_str, mlen);
	HexStrToByteArr(in, in_str, dlen);

	if(mode == 0)
	{
		for(i = 0; i<(dlen/2)/8; i++)
			Des_Encrypt(in+8*i, in+8*i, key);
	}
	else 
	{
		for(i = 0; i<(dlen/2)/8; i++)
			Des_Decrypt(in+8*i, in+8*i, key);
	}

    for(i=0; i<dlen/2; i++)
        sprintf(tmp+2*i, "%02x", in[i]);

    Tcl_SetObjResult(interp, Tcl_NewStringObj(tmp, -1));

    return TCL_OK;
}


int SM4EcbCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    char *in_str, *key_str;
    unsigned char key[32], in[0x200];
	char tmp[0x401];
    int mlen, i, mode, dlen;

	Crypto_Init(interp);

    if(objc != 4)
    {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("Error: [sm4ecb mode key data]  The number of args must be 3.", -1));
        return TCL_ERROR;
    }

    if(Tcl_GetIntFromObj(interp, objv[1], &mode) != TCL_OK) 
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error: [sm4ecb mode key data]  The arg mode should be an interger(00-encrypt, 01-decrypt).", -1));
        return TCL_ERROR;
    }
	if((mode != 0) &&(mode != 1))
	{
		Tcl_SetObjResult(interp, Tcl_NewStringObj("Error: [sm4ecb mode key data] The arg mode should be an interger(00-encrypt, 01-decrypt).", -1));
        return TCL_ERROR;
	}

    key_str = Tcl_GetStringFromObj(objv[2], &mlen);
    if(mlen != 32)
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error: [sm4ecb mode key data]  The length of arg key should be 16 Bytes.", -1));
        return TCL_ERROR;
    }

    in_str = Tcl_GetStringFromObj(objv[3], &dlen);
    if(dlen%32)
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error: [sm4ecb mode key data] The length of arg data should be multiple of 16 Bytes.", -1));
        return TCL_ERROR;
    }

	HexStrToByteArr(key, key_str, mlen);
	HexStrToByteArr(in, in_str, dlen);

    for(i = 0; i<(dlen/2)/16; i++)
        SM4_ECB(in+16*i, in+16*i, key, mode);

    for(i=0; i<dlen/2; i++)
        sprintf(tmp+2*i, "%02x", in[i]);

    Tcl_SetObjResult(interp, Tcl_NewStringObj(tmp, -1));

    return TCL_OK;
}


int MD5Cmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    MD5_CTX ctx;
    char *Message, str[0x200];
	int mlen;
    unsigned char tmp[0x200];
    int i;

	Crypto_Init(interp);
	
	if( objc != 2)
	{
		Tcl_SetResult( interp,"Usage: md5 Message.\nThe number of arguments need be 1.",TCL_VOLATILE );
		return TCL_ERROR;
	}

    Message = Tcl_GetStringFromObj(objv[1], &mlen);
	
	if(mlen%2)
	{
		Tcl_SetResult( interp,"Usage: md5 Message.\nThe length of argument Message must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

    MD5Init(&ctx);
	
    for(i = 0; i < (mlen/0x100); i++)
    {
		HexStrToByteArr(tmp, Message+0x100*i, 0x100);
        MD5Update(&ctx, tmp, 0x80);
    }
    if(mlen%0x100)
    {
		HexStrToByteArr(tmp, Message+0x100*i, mlen%0x100);
        MD5Update(&ctx, tmp, (mlen%0x100)/2);
    }

    MD5Final(tmp, &ctx);

    for(i=0; i<16; i++)
        sprintf(str+2*i, "%02x", tmp[i]);

    Tcl_SetObjResult(interp, Tcl_NewStringObj(str, -1));

    return TCL_OK;
}


int SM3HashCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    SM3_CTX ctx;
    char *Message, str[0x80];
	int mlen;
    unsigned char tmp[0x80];
    int i;

	Crypto_Init(interp);
	
	if( objc != 2)
	{
		Tcl_SetResult( interp,"Error: [sm3 Message] The number of arguments need be 1.",TCL_VOLATILE );
		return TCL_ERROR;
	}

    Message = Tcl_GetStringFromObj(objv[1], &mlen);
	
	if(mlen%2)
	{
		Tcl_SetResult( interp,"Error: [sm3 Message] The length of argument Message must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}

    sm3_init(&ctx, 256);
	
    for(i = 0; i < (mlen/0x100); i++)
    {
		HexStrToByteArr(tmp, Message+0x100*i, 0x100);
        sm3_update(&ctx, tmp, 0x80);
    }
    if(mlen%0x100)
    {
		HexStrToByteArr(tmp, Message+0x100*i, mlen%0x100);
        sm3_update(&ctx, tmp, (mlen%0x100)/2);
    }

    sm3_final(&ctx, tmp);

    for(i=0; i<32; i++)
        sprintf(str+2*i, "%02x", tmp[i]);

    Tcl_SetObjResult(interp, Tcl_NewStringObj(str, -1));

    return TCL_OK;
}


int SHashCmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    Hash_CTX256 ctx;
	Hash_CTX512 ctx1;
    char *Message, str[0x200];
	int mlen;
    unsigned char tmp[0x200];
    int i, mode;
	unsigned char hmode;

	Crypto_Init(interp);
	
	if( objc != 3)
	{
		Tcl_SetResult( interp,"Usage: sha mode Message.\nThe number of arguments need be 2.",TCL_VOLATILE );
		return TCL_ERROR;
	}

    if(Tcl_GetIntFromObj(interp, objv[1], &mode) != TCL_OK) 
    {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("Error: sha Argument Mode should be an interger(1 224 256 384 512).", -1));
        return TCL_ERROR;
    }
	if((mode != 1) &&(mode != 224)&&(mode != 256)&&(mode != 384)&&(mode != 512))
	{
		Tcl_SetObjResult(interp, Tcl_NewStringObj("Error: sha Argument Mode should be an interger(1 224 256 384 512).", -1));
        return TCL_ERROR;
	}

    Message = Tcl_GetStringFromObj(objv[2], &mlen);
	if(mlen%2)
	{
		Tcl_SetResult( interp,"Usage: sha mode Message.\nThe length of argument Message must be even",TCL_VOLATILE );
		return TCL_ERROR;
	}
	
	if(mode == 1)
	{
		mode = 160;
		hmode = 1;			//sha1
	}
	else if(mode == 224)
		hmode = 2;			//sha224
	else if(mode == 256)
		hmode = 3;			//sha256
	else if(mode == 384)
		hmode = 4;			//sha384
	else
		hmode = 5;			//sha512

	if(hmode<4)
	{
		Hash_Init(&ctx, hmode);
		for(i = 0; i < (mlen/0x100); i++)
		{
			HexStrToByteArr(tmp, Message+0x100*i, 0x100);
			Hash_Update(&ctx, tmp, 0x80);
		}
		if(mlen%0x100)
		{
			HexStrToByteArr(tmp, Message+0x100*i, mlen%0x100);
			Hash_Update(&ctx, tmp, (mlen%0x100)/2);
		}

		Hash_Final(&ctx, tmp);
	}
	else
	{
		Hash_Init1(&ctx1, hmode);
	
		for(i = 0; i < (mlen/0x100); i++)
		{
			HexStrToByteArr(tmp, Message+0x100*i, 0x100);
			Hash_Update1(&ctx1, tmp, 0x80);
		}
		if(mlen%0x100)
		{
			HexStrToByteArr(tmp, Message+0x100*i, mlen%0x100);
			Hash_Update1(&ctx1, tmp, (mlen%0x100)/2);
		}

		Hash_Final1(&ctx1, tmp);
	}
		

    for(i=0; i<mode/8; i++)
        sprintf(str+2*i, "%02x", tmp[i]);

    Tcl_SetObjResult(interp, Tcl_NewStringObj(str, -1));

    return TCL_OK;
}

int DLLEXPORT
Crypto_Init(Tcl_Interp* interp)
{
	if(Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL) {
		return TCL_ERROR;
	}

	Tcl_CreateObjCommand(interp, "version",(Tcl_ObjCmdProc *)VersionCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "add",(Tcl_ObjCmdProc *)AddCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "sub",(Tcl_ObjCmdProc *)SubCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "mul",(Tcl_ObjCmdProc *)MulCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "div",(Tcl_ObjCmdProc *)DivCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "rem",(Tcl_ObjCmdProc *)RemCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "cmp",(Tcl_ObjCmdProc *)CmpCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "orr",(Tcl_ObjCmdProc *)OrrCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "and",(Tcl_ObjCmdProc *)AndCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "not",(Tcl_ObjCmdProc *)NotCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "xor",(Tcl_ObjCmdProc *)XorCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "sft",(Tcl_ObjCmdProc *)SftCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "gcd",(Tcl_ObjCmdProc *)GcdCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "isprime",(Tcl_ObjCmdProc *)IsPrimeCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "genprime",(Tcl_ObjCmdProc *)GenPrimeCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "modadd",(Tcl_ObjCmdProc *)ModAddCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "modsub",(Tcl_ObjCmdProc *)ModSubCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "modmul",(Tcl_ObjCmdProc *)ModMulCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "modinv",(Tcl_ObjCmdProc *)ModInvCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "modexp",(Tcl_ObjCmdProc *)ModExpCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "ispoint",(Tcl_ObjCmdProc *)PointInCurveCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "padd",(Tcl_ObjCmdProc *)PointAddCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "pmul",(Tcl_ObjCmdProc *)PointMulCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

	Tcl_CreateObjCommand(interp, "mpmul",(Tcl_ObjCmdProc *)EcMultPointMulCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "rng",(Tcl_ObjCmdProc *)RngCmd, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "aesecb",(Tcl_ObjCmdProc *)AESEcbCmd, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "desecb",(Tcl_ObjCmdProc *)DESEcbCmd, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "sm4ecb",(Tcl_ObjCmdProc *)SM4EcbCmd, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "md5",(Tcl_ObjCmdProc *)MD5Cmd, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "sm3",(Tcl_ObjCmdProc *)SM3HashCmd,(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	Tcl_CreateObjCommand(interp, "sha",(Tcl_ObjCmdProc *)SHashCmd, (ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

	if(Tcl_PkgProvide(interp, "crypto", "1.0.0") == TCL_ERROR) {
		return TCL_ERROR;
	}
	return TCL_OK;
}


