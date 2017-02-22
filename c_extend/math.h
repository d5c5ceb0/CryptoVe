/* 
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */
#ifndef MATH_H_
#define MATH_H_

int Add( char *inParamList[], char *strOutPut);

int Sub( char *inParamList[], char *strOutPut);

int Mul(char *inParamList[], char *strOutPut);

int Div(char *inParamList[], char *strOutPut);

int Rem(char *inParamList[], char *strOutPut);

int Cmp(char *inParamList[], char *strOutPut);

int Sft(char *inParamList[], char *strOutPut);

int Gcd(char *inParamList[], char *strOutPut);

int IsPrime(char *inParamList[], char *strOutPut);

int GenPrime(char *inParamList[], char *strOutPut);

int ModAdd(char *inParamList[], char *strOutPut);

int ModSub(char *inParamList[], char *strOutPut);

int ModMul(char *inParamList[], char *strOutPut);

int ModInv(char *inParamList[], char *strOutPut);

int ModExp(char *inParamList[], char *strOutPut);

int IsPointInCurve(char *inParamList[], char *strOutPut);

int EcPointAdd(char *inParamList[], char *strOutPut);

int EcPointMul(char *inParamList[], char *strOutPut);

int EcMultPointMul(char *inParamList[], char *strOutPut);

int Rng(char *inParamList[], char *strOutPut);

#endif

