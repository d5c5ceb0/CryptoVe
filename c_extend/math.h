#ifndef MATH_H_
#define MATH_H_

//Add函数
//大数加法运算，格式strOutPut = inParamList[0] + inParamList[1]
//inParamList(in) 字符串容器，用于保存加法的两个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Add( char *inParamList[], char *strOutPut);


//Sub函数
//大数减法运算，格式strOutPut = inParamList[0] - inParamList[1]
//inParamList(in) 字符串容器，用于保存减法的两个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Sub( char *inParamList[], char *strOutPut);


//Mul函数
//大数乘法运算，格式strOutPut = inParamList[0] * inParamList[1]
//inParamList(in) 字符串容器，用于保存乘法的两个运算参数。
//strOutPut(out) 用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Mul(char *inParamList[], char *strOutPut);


//Div函数
//大数除法运算，格式strOutPut = inParamList[0] / inParamList[1]
//inParamList(in) 字符串容器，用于保存除法的两个运算参数。
//strOutPut(out) 用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Div(char *inParamList[], char *strOutPut);


//Rem函数
//大数取模运算，格式strOutPut = inParamList[0] % inParamList[1]
//inParamList(in) 字符串容器，用于保存模运算的两个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Rem(char *inParamList[], char *strOutPut);


//Cmp函数
//大数比较运算，格式strOutPut = inParamList[0] ?= (> or <) inParamList[1]
//inParamList(in) 字符串容器，用于保存模运算的二个运算参数。
//strOutPut(out) 用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Cmp(char *inParamList[], char *strOutPut);

//Sft函数
//大数移位运算，格式strOutPut = inParamList[1] >>(or <<)inParamList[2]
//inParamList(in) 字符串容器，用于保存模运算的三个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Sft(char *inParamList[], char *strOutPut);

//Gcd函数
//最大公约数运算，格式strOutPut = GCD(inParamList[0] ,inParamList[1])
//inParamList(in) 字符串容器，用于计算最大公约数的两个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Gcd(char *inParamList[], char *strOutPut);


//IsPrime函数
//素性检测，格式strOutPut = IsPrime(inParamList[0])
//inParamList(in) 字符串容器，用于验证素性的参数。
//strOutPut(out) 用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int IsPrime(char *inParamList[], char *strOutPut);


//GenPrime函数
//产生素数。
//inParamList(in) 字符串容器，用于多点乘运算的2个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int GenPrime(char *inParamList[], char *strOutPut);


//ModAdd函数
//大数模加运算，格式strOutPut = inParamList[0] + inParamList[1] mod inParamList[2]
//inParamList(in) 字符串容器，用于模加运算的3个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int ModAdd(char *inParamList[], char *strOutPut);


//ModSub函数
//大数模减运算，格式strOutPut = inParamList[0] - inParamList[1] mod inParamList[2]
//inParamList(in) 字符串容器，用于模减运算的3个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int ModSub(char *inParamList[], char *strOutPut);


//ModMul函数
//大数模乘运算，格式strOutPut = inParamList[0] * inParamList[1] mod inParamList[2]
//inParamList(in) 字符串容器，用于模乘运算的3个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int ModMul(char *inParamList[], char *strOutPut);


//ModInv函数
//大数模逆运算，格式strOutPut = inParamList[0] ^ -1 mod inParamList[1]
//inParamList(in) 字符串容器，用于模逆运算的2个运算参数。
//strOutPut(out)         用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int ModInv(char *inParamList[], char *strOutPut);


//ModExp函数
//大数模幂运算，格式strOutPut = inParamList[0] ^ inParamList[1] mod inParamList[2]
//vector<string> inParamList(in) 字符串容器，用于模幂运算的3个运算参数。
//string& strOutPut(out)         用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int ModExp(char *inParamList[], char *strOutPut);


//EcPointInCurve函数
//判断点在曲线上。
//格式strOutPut = IsPointInCurve(g)
//椭圆曲线方程: y^2 = x^3 + inParamList[2]x + inParamList[3] mod inParamList[4]
//inParamList(in) 字符串容器，用于点乘运算的运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int IsPointInCurve(char *inParamList[], char *strOutPut);


//EcPointAdd函数
//椭圆曲线点加(倍点)运算。
//格式strOutPut = (inParamList[0],inParamList[1]) + (inParamList[2],inParamList[3])
//椭圆曲线方程: y^2 = x^3 + inParamList[4]x + inParamList[5] mod inParamList[6]
//inParamList(in) 字符串容器，用于点加运算的7个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int EcPointAdd(char *inParamList[], char *strOutPut);


//EcPointMul函数
//椭圆曲线点乘(标量乘)运算。
//格式strOutPut = [inParamList[0]](inParamList[1],inParamList[2])
//椭圆曲线方程: y^2 = x^3 + inParamList[3]x + inParamList[4] mod inParamList[5]
//inParamList(in) 字符串容器，用于点乘运算的6个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int EcPointMul(char *inParamList[], char *strOutPut);


//EcMultPointMul函数
//椭圆曲线多点乘运算。
//格式strOutPut = [inParamList[0]](inParamList[1],inParamList[2]) + [inParamList[3]](inParamList[4],inParamList[5])
//椭圆曲线方程: y^2 = x^3 + inParamList[6]x + inParamList[7] mod inParamList[8]
//inParamList(in) 字符串容器，用于多点乘运算的9个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int EcMultPointMul(char *inParamList[], char *strOutPut);


//Rng函数
//产生随机数。
//inParamList(in) 字符串容器，用于多点乘运算的2个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Rng(char *inParamList[], char *strOutPut);
#endif

