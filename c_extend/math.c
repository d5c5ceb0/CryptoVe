#include "miracl.h"
#include "mirdef.h"     
#include <string.h>
#include <time.h>

//Add函数
//大数加法运算，格式strOutPut = inParamList[0] + inParamList[1]
//inParamList(in) 字符串容器，用于保存加法的两个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Add(char *inParamList[], char *strOutPut)
{
	big a, b, r;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
    b=mirvar(0);
	r=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);  

	//r = a + b
	add(a,  b,  r);
	cotstr(r, strOutPut);

	mirkill(a);
	mirkill(b);
	mirkill(r);
	mirexit();

	return 0;
}


//Sub函数
//大数减法运算，格式strOutPut = inParamList[0] - inParamList[1]
//inParamList(in) 字符串容器，用于保存减法的两个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Sub(char *inParamList[], char *strOutPut)
{
	big a, b, r;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
    b=mirvar(0);
	r=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);  

	//r = a - b
	subtract(a,  b,  r);
	cotstr(r, strOutPut);

	mirkill(a);
	mirkill(b);
	mirkill(r);
	mirexit();

	return 0;
}

//Mul函数
//大数乘法运算，格式strOutPut = inParamList[0] * inParamList[1]
//inParamList(in) 字符串容器，用于保存乘法的两个运算参数。
//strOutPut(out) 用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Mul(char *inParamList[], char *strOutPut)
{
	big a, b, r;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
    b=mirvar(0);
	r=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);  

	//r = a * b
	multiply(a,  b,  r);
	cotstr(r, strOutPut);

	mirkill(a);
	mirkill(b);
	mirkill(r);
	mirexit();

	return 0;
}


//Div函数
//大数除法运算，格式strOutPut = inParamList[0] / inParamList[1]
//inParamList(in) 字符串容器，用于保存除法的两个运算参数。
//strOutPut(out) 用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Div(char *inParamList[], char *strOutPut)
{
	big a, b;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
    b=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);  

	//r = a / b
	divide(a,  b,  a);
	cotstr(a, strOutPut);

	mirkill(a);
	mirkill(b);
	mirexit();

	return 0;
}

//Rem函数
//大数取模运算，格式strOutPut = inParamList[0] % inParamList[1]
//inParamList(in) 字符串容器，用于保存模运算的两个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Rem(char *inParamList[], char *strOutPut)
{
	big a, b;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
    b=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);  

	//r = a % b
	divide(a,  b,  b);
	cotstr(a, strOutPut);

	mirkill(a);
	mirkill(b);
	mirexit();

	return 0;
}

//Cmp函数
//大数比较运算，格式strOutPut = inParamList[0] ?= (> or <) inParamList[1]
//inParamList(in) 字符串容器，用于保存模运算的二个运算参数。
//strOutPut(out) 用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Cmp(char *inParamList[], char *strOutPut)
{
	int r;
	big a, b;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
    b=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);  

	r = mr_compare(a, b);
	if(r == -1)
		r = 2;

	sprintf(strOutPut, "%d", r);

	mirkill(a);
	mirkill(b);
	mirexit();

	return 0;
}


//Sft函数
//大数移位运算，格式strOutPut = inParamList[1] >>(or <<)inParamList[2]
//inParamList(in) 字符串容器，用于保存模运算的三个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Sft(char *inParamList[], char *strOutPut)
{
	int b;
	big a, r;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
	r=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[1]);

	sscanf((char *)inParamList[2], "%d", &b);

	if((inParamList[0][0] == 'R') || (inParamList[0][0] == 'r'))	//右移
	{
		b = -b;
	}

	sftbit(a,  b,  r);
	cotstr(r, strOutPut);


	mirkill(a);
	mirkill(r);
	mirexit();

	return 0;
}
//Gcd函数
//最大公约数运算，格式strOutPut = GCD(inParamList[0] ,inParamList[1])
//inParamList(in) 字符串容器，用于计算最大公约数的两个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Gcd(char *inParamList[], char *strOutPut)
{
	big a, b, r;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
    b=mirvar(0);
	r=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);  


	egcd(a,  b,  r);
	cotstr(r, strOutPut);

	mirkill(a);
	mirkill(b);
	mirkill(r);
	mirexit();

	return 0;
}


//IsPrime函数
//素性检测，格式strOutPut = IsPrime(inParamList[0])
//inParamList(in) 字符串容器，用于验证素性的参数。
//strOutPut(out) 用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int IsPrime(char *inParamList[], char *strOutPut)
{
	big a;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);

	if(isprime(a) ==TRUE)
		strcpy(strOutPut, "1");
	else
		strcpy(strOutPut, "0");

	mirkill(a);
	mirexit();

	return 0;
}


//GenPrime函数
//产生素数。
//inParamList(in) 字符串容器，用于多点乘运算的2个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int GenPrime(char *inParamList[], char *strOutPut)
{
	big base;
	big out;
	
	miracl *mip = mirsys(4096, 16);
	base=mirvar(0);
	out=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(base,(char *)inParamList[0]);

	nxprime(base, out);

	cotstr(out, strOutPut);

	mirkill(base);
	mirkill(out);
	mirexit();

	return 0;
}


//ModAdd函数
//大数模加运算，格式strOutPut = inParamList[0] + inParamList[1] mod inParamList[2]
//inParamList(in) 字符串容器，用于模加运算的3个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int ModAdd(char *inParamList[], char *strOutPut)
{
	big a, b, n, r, tmp;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
	b=mirvar(0);
    n=mirvar(0);
	r=mirvar(0);
	tmp=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);
	cinstr(n,(char *)inParamList[2]);  

	//The parameter n must be positive and odd?
	if(subdivisible(n, 2))
	{
		mirkill(a);
		mirkill(b);
		mirkill(n);
		mirkill(r);
		mirkill(tmp);
		mirexit();

		strcpy(strOutPut, "Error: modadd, The parameter n must be positive and odd.");
		return 1;
	}

	//r = a+b mod n
	prepare_monty(n);
	copy(a, tmp);     // a对n的剩余，保存在tmp中，下同
	nres(tmp, a);
	copy(b, tmp);
	nres(tmp, b);
	nres_modadd(a, b, r);
	redc(r, tmp);
	cotstr(tmp, strOutPut);

	mirkill(a);
	mirkill(b);
	mirkill(n);
	mirkill(r);
	mirkill(tmp);
	mirexit();

	return 0;
}


//ModSub函数
//大数模减运算，格式strOutPut = inParamList[0] - inParamList[1] mod inParamList[2]
//inParamList(in) 字符串容器，用于模减运算的3个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int ModSub(char *inParamList[], char *strOutPut)
{
	big a, b, n, r, tmp;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
	b=mirvar(0);
    n=mirvar(0);
	r=mirvar(0);
	tmp=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);
	cinstr(n,(char *)inParamList[2]);  

	//The parameter n must be positive and odd?
	if(subdivisible(n, 2))
	{
		mirkill(a);
		mirkill(b);
		mirkill(n);
		mirkill(r);
		mirkill(tmp);
		mirexit();

		strcpy(strOutPut, "Error: modsub, The parameter n must be positive and odd.");
		return 1;
	}

	//r = a-b mod n
	prepare_monty(n);
	copy(a, tmp);     // a对n的剩余，保存在tmp中，下同
	nres(tmp, a);
	copy(b, tmp);
	nres(tmp, b);
	nres_modsub(a, b, r);
	redc(r, tmp);
	cotstr(tmp, strOutPut);

	mirkill(a);
	mirkill(b);
	mirkill(n);
	mirkill(r);
	mirkill(tmp);
	mirexit();

	return 0;
}


//ModMul函数
//大数模乘运算，格式strOutPut = inParamList[0] * inParamList[1] mod inParamList[2]
//inParamList(in) 字符串容器，用于模乘运算的3个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int ModMul(char *inParamList[], char *strOutPut)
{
	big a, b, n, r, tmp;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
	b=mirvar(0);
    n=mirvar(0);
	r=mirvar(0);
	tmp=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);
	cinstr(n,(char *)inParamList[2]);  

	//The parameter n must be positive and odd?
	if(subdivisible(n, 2))
	{
		mirkill(a);
		mirkill(b);
		mirkill(n);
		mirkill(r);
		mirkill(tmp);
		mirexit();

		strcpy(strOutPut, "Error: modmul, The parameter n must be positive and odd.");
		return 1;
	}

	//r = a*b mod n
	prepare_monty(n);
	copy(a, tmp);     // a对n的剩余，保存在tmp中，下同
	nres(tmp, a);
	copy(b, tmp);
	nres(tmp, b);
	nres_modmult(a, b, r);
	redc(r, tmp);
	cotstr(tmp, strOutPut);

	mirkill(a);
	mirkill(b);
	mirkill(n);
	mirkill(r);
	mirkill(tmp);
	mirexit();

	return 0;
}

//ModInv函数
//大数模逆运算，格式strOutPut = inParamList[0] ^ -1 mod inParamList[1]
//inParamList(in) 字符串容器，用于模逆运算的2个运算参数。
//strOutPut(out)         用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int ModInv(char *inParamList[], char *strOutPut)
{
	big a, n, r, tmp;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
    n=mirvar(0);
	r=mirvar(0);
	tmp=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(n,(char *)inParamList[1]);  

	//The parameter n must be prime
	egcd(a, n, r);
	convert(1, tmp);
	if(mr_compare(r,tmp))
	{
		mirkill(a);
		mirkill(n);
		mirkill(r);
		mirkill(tmp);
		mirexit();

		strcpy(strOutPut, "Error: modinv, The parameter n must be co-prime with a.");
		return 1;
	}

	//r = a^-1 mod n
	//prepare_monty(n);
	xgcd(a,  n,  r,  r,  r);
	cotstr(r, strOutPut);

	mirkill(a);
	mirkill(n);
	mirkill(r);
	mirkill(tmp);
	mirexit();

	return 0;
}

//ModExp函数
//大数模幂运算，格式strOutPut = inParamList[0] ^ inParamList[1] mod inParamList[2]
//vector<string> inParamList(in) 字符串容器，用于模幂运算的3个运算参数。
//string& strOutPut(out)         用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int ModExp(char *inParamList[], char *strOutPut)
{
	big a, b, n, r, tmp;

	miracl *mip = mirsys(4096, 16);
	a=mirvar(0);
	b=mirvar(0);
    n=mirvar(0);
	r=mirvar(0);
	tmp=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	cinstr(a,(char *)inParamList[0]);
	cinstr(b,(char *)inParamList[1]);
	cinstr(n,(char *)inParamList[2]);  

	//The parameter n must be positive and odd?
	if(subdivisible(n, 2))
	{
		mirkill(a);
		mirkill(b);
		mirkill(n);
		mirkill(r);
		mirkill(tmp);
		mirexit();

		strcpy(strOutPut, "Error: modexp, The parameter n must be positive and odd.");
		return 1;
	}

	//r = a^b mod n
	prepare_monty(n);
	copy(a, tmp);     // a对n的剩余，保存在tmp中，下同
	nres(tmp, a);
	nres_powmod(a, b, r);
	redc(r, tmp);
	cotstr(tmp, strOutPut);

	mirkill(a);
	mirkill(b);
	mirkill(n);
	mirkill(r);
	mirkill(tmp);
	mirexit();

	return 0;
}

//EcPointInCurve函数
//判断点在曲线上。
//格式strOutPut = IsPointInCurve(g)
//椭圆曲线方程: y^2 = x^3 + inParamList[2]x + inParamList[3] mod inParamList[4]
//inParamList(in) 字符串容器，用于点乘运算的运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int IsPointInCurve(char *inParamList[], char *strOutPut)
{
	big a, b, p, gx, gy;

	miracl *mip = mirsys(4096, 16);
	epoint *g =  epoint_init();
	a=mirvar(0);
	b=mirvar(0);
	p=mirvar(0);
	gx=mirvar(0);
	gy=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	//cinstr(a,"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
	//cinstr(b,"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
	//cinstr(p,"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
	//cinstr(d,"40001424830214204288024A10148000021C0009835821AC8000A0131100A859");
	//cinstr(gx,"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
	//cinstr(gy,"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
	cinstr(gx,(char *)inParamList[0]);
	cinstr(gy,(char *)inParamList[1]);
	cinstr(p, (char *)inParamList[2]);
	cinstr(a, (char *)inParamList[3]);
	cinstr(b, (char *)inParamList[4]);

	ecurve_init(a, b, p, MR_AFFINE);
    if(epoint_set(gx,  gy,  1,  g) == TRUE)
		strcpy(strOutPut, "01");
	else
		strcpy(strOutPut, "00");


	mirkill(a);
	mirkill(b);
	mirkill(p);
	mirkill(gx);
	mirkill(gy);
	epoint_free(g);
	mirexit();

	return 0;
}

//EcPointAdd函数
//椭圆曲线点加(倍点)运算。
//格式strOutPut = (inParamList[0],inParamList[1]) + (inParamList[2],inParamList[3])
//椭圆曲线方程: y^2 = x^3 + inParamList[4]x + inParamList[5] mod inParamList[6]
//inParamList(in) 字符串容器，用于点加运算的7个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int EcPointAdd(char *inParamList[], char *strOutPut)
{
	int i;
	char str[4097];
	int str_len, out_len;
	big a, b, p, ax, ay, bx, by;

	miracl *mip = mirsys(4096, 16);
	epoint *pa =  epoint_init();
	epoint *pb =  epoint_init();
	a=mirvar(0);
	b=mirvar(0);
	p=mirvar(0);
    ax=mirvar(0);
	ay=mirvar(0);
	bx=mirvar(0);
	by=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 

	cinstr(ax,(char *)inParamList[0]);
	cinstr(ay,(char *)inParamList[1]);
	cinstr(bx,(char *)inParamList[2]);
	cinstr(by,(char *)inParamList[3]);
	cinstr(p, (char *)inParamList[4]);
	cinstr(a, (char *)inParamList[5]);
	cinstr(b, (char *)inParamList[6]);

	out_len = strlen(inParamList[4]);

	ecurve_init(a, b, p, MR_AFFINE);
    if(epoint_set(ax,  ay,  1,  pa) != TRUE)
	{
		strcpy(strOutPut, "Usage: padd, Point is not in curve");
		mirkill(a);
		mirkill(b);
		mirkill(p);
		mirkill(ax);
		mirkill(ay);
		mirkill(bx);
		mirkill(by);
		epoint_free(pa);
		epoint_free(pb);
		mirexit();
		return 1;
	}

	if(epoint_set(bx,  by,  1,  pb) != TRUE)
	{
		strcpy(strOutPut, "Usage: padd, Point is not in curve");
		mirkill(a);
		mirkill(b);
		mirkill(p);
		mirkill(ax);
		mirkill(ay);
		mirkill(bx);
		mirkill(by);
		epoint_free(pa);
		epoint_free(pb);
		mirexit();
		return 1;
	}

	ecurve_add(pa, pb);
	i = epoint_get(pb, bx, by); 

	cotstr(bx, str);
	str_len = strlen(str);
	memset(strOutPut, '0', out_len);
	memcpy(strOutPut+(out_len-str_len), str, str_len);

	cotstr(by, str);
	str_len = strlen(str);
	memset(strOutPut+out_len, '0', out_len);
	memcpy(strOutPut+(2*out_len-str_len), str, str_len);
	strOutPut[2*out_len] = '\0';

	mirkill(a);
	mirkill(b);
	mirkill(p);
	mirkill(ax);
	mirkill(ay);
	mirkill(bx);
	mirkill(by);
	epoint_free(pa);
	epoint_free(pb);
	mirexit();

	return 0;
}

//EcPointMul函数
//椭圆曲线点乘(标量乘)运算。
//格式strOutPut = [inParamList[0]](inParamList[1],inParamList[2])
//椭圆曲线方程: y^2 = x^3 + inParamList[3]x + inParamList[4] mod inParamList[5]
//inParamList(in) 字符串容器，用于点乘运算的6个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int EcPointMul(char *inParamList[], char *strOutPut)
{
	int i;
	char str[4097];
	int str_len, out_len;
	big a, b, p, d, gx, gy, qx, qy;

	miracl *mip = mirsys(4096, 16);
	epoint *g =  epoint_init();
	epoint *q =  epoint_init();
	a=mirvar(0);
	b=mirvar(0);
	p=mirvar(0);
    d=mirvar(0);
	gx=mirvar(0);
	gy=mirvar(0);
	qx=mirvar(0);
	qy=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	//cinstr(a,"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
	//cinstr(b,"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
	//cinstr(p,"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
	//cinstr(d,"40001424830214204288024A10148000021C0009835821AC8000A0131100A859");
	//cinstr(gx,"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
	//cinstr(gy,"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
	cinstr(d ,(char *)inParamList[0]);
	cinstr(gx,(char *)inParamList[1]);
	cinstr(gy,(char *)inParamList[2]);
	cinstr(p ,(char *)inParamList[3]);
	cinstr(a ,(char *)inParamList[4]);
	cinstr(b ,(char *)inParamList[5]);

	out_len = strlen(inParamList[3]);

	ecurve_init(a, b, p, MR_AFFINE);
    if(epoint_set(gx,  gy,  1,  g) != TRUE)
	{
		strcpy(strOutPut, "Usage: pmul, Point is not in curve");
		mirkill(a);
		mirkill(b);
		mirkill(p);
		mirkill(d);
		mirkill(gx);
		mirkill(gy);
		mirkill(qx);
		mirkill(qy);
		epoint_free(g);
		epoint_free(q);
		mirexit();
		return 1;
	}

	ecurve_mult(d, g, q);
	i = epoint_get(q, qx, qy); 

	cotstr(qx, str);
	str_len = strlen(str);
	memset(strOutPut, '0', out_len);
	memcpy(strOutPut+(out_len-str_len), str, str_len);

	cotstr(qy, str);
	str_len = strlen(str);
	memset(strOutPut+out_len, '0', out_len);
	memcpy(strOutPut+(2*out_len-str_len), str, str_len);
	strOutPut[2*out_len] = '\0';


	mirkill(a);
	mirkill(b);
	mirkill(p);
	mirkill(d);
	mirkill(gx);
	mirkill(gy);
	mirkill(qx);
	mirkill(qy);
	epoint_free(g);
	epoint_free(q);
	mirexit();

	return 0;
}


//EcMultPointMul函数
//椭圆曲线多点乘运算。
//格式strOutPut = [inParamList[0]](inParamList[1],inParamList[2]) + [inParamList[3]](inParamList[4],inParamList[5])
//椭圆曲线方程: y^2 = x^3 + inParamList[6]x + inParamList[7] mod inParamList[8]
//inParamList(in) 字符串容器，用于多点乘运算的9个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int EcMultPointMul(char *inParamList[], char *strOutPut)
{
	int i;
	char str[4097];
	int str_len, out_len;
	big a, b, p, d, gx, gy, da, gax, gay, qx, qy;

	miracl *mip = mirsys(4096, 16);
	epoint *g =  epoint_init();
	epoint *ga = epoint_init();
	epoint *q =  epoint_init();
	a=mirvar(0);
	b=mirvar(0);
	p=mirvar(0);
    d=mirvar(0);
	gx=mirvar(0);
	gy=mirvar(0);
	da=mirvar(0);
	gax=mirvar(0);
	gay=mirvar(0);
	qx=mirvar(0);
	qy=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 
	//cinstr(a,"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
	//cinstr(b,"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
	//cinstr(p,"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
	//cinstr(d,"40001424830214204288024A10148000021C0009835821AC8000A0131100A859");
	//cinstr(gx,"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
	//cinstr(gy,"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
	cinstr(d,  (char *)inParamList[0]);
	cinstr(gx, (char *)inParamList[1]);
	cinstr(gy, (char *)inParamList[2]);
	cinstr(da, (char *)inParamList[3]);
	cinstr(gax,(char *)inParamList[4]);
	cinstr(gay,(char *)inParamList[5]);
	cinstr(p,  (char *)inParamList[6]);
	cinstr(a,  (char *)inParamList[7]);
	cinstr(b,  (char *)inParamList[8]);

	out_len = strlen(inParamList[6]);

	ecurve_init(a, b, p, MR_AFFINE);
    if(epoint_set(gx,  gy,  1,  g) != TRUE)
	{
		strcpy(strOutPut, "Usage: mpmul, Point is not in curve");
		mirkill(a);
		mirkill(b);
		mirkill(p);
		mirkill(d);
		mirkill(gx);
		mirkill(gy);
		mirkill(da);
		mirkill(gax);
		mirkill(gay);
		mirkill(qx);
		mirkill(qy);
		epoint_free(g);
		epoint_free(ga);
		epoint_free(q);
		mirexit();
		return 1;
	}

	if(epoint_set(gax,  gay,  1,  ga) != TRUE)
	{
		strcpy(strOutPut, "Usage: mpmul, Point is not in curve");
		mirkill(a);
		mirkill(b);
		mirkill(p);
		mirkill(d);
		mirkill(gx);
		mirkill(gy);
		mirkill(da);
		mirkill(gax);
		mirkill(gay);
		mirkill(qx);
		mirkill(qy);
		epoint_free(g);
		epoint_free(ga);
		epoint_free(q);
		mirexit();
		return 1;
	}

	ecurve_mult2(d, g, da, ga, q);
	i = epoint_get(q, qx, qy); 

	cotstr(qx, str);
	str_len = strlen(str);
	memset(strOutPut, '0', out_len);
	memcpy(strOutPut+(out_len-str_len), str, str_len);

	cotstr(qy, str);
	str_len = strlen(str);
	memset(strOutPut+out_len, '0', out_len);
	memcpy(strOutPut+(2*out_len-str_len), str, str_len);
	strOutPut[2*out_len] = '\0';

	mirkill(a);
	mirkill(b);
	mirkill(p);
	mirkill(d);
	mirkill(gx);
	mirkill(gy);
	mirkill(da);
	mirkill(gax);
	mirkill(gay);
	mirkill(qx);
	mirkill(qy);
	epoint_free(g);
	epoint_free(ga);
	epoint_free(q);
	mirexit();

	return 0;
}


//Rng函数
//产生随机数。
//inParamList(in) 字符串容器，用于多点乘运算的2个运算参数。
//strOutPut(out)  用于输出字符串形式的结果。
//运算正确返回0，错误返回1
int Rng(char *inParamList[], char *strOutPut)
{
	int rlen, ilen;
	char str[4096];
	big out;
	csprng rng;
	

	miracl *mip = mirsys(4096, 16);
	out=mirvar(0);
	mip->IOBASE=16;	// input large hex number into big x 

	sscanf((char *)inParamList[0], "%d", &rlen);
	//printf("%d\n", rlen);
	//printf("%s\n", (char *)inParamList[0].c_str());
	ilen= strlen(inParamList[1]);
	strong_init(&rng, ilen, (char *)inParamList[1], (mr_unsign32)time(0));
	strong_bigdig(&rng, rlen*2, 16, out);
	strong_kill(&rng);

	cotstr(out, str);
	strOutPut = str;

	mirkill(out);
	mirexit();

	return 0;
}

