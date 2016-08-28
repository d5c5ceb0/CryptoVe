#ifndef MATH_H_
#define MATH_H_

//Add����
//�����ӷ����㣬��ʽstrOutPut = inParamList[0] + inParamList[1]
//inParamList(in) �ַ������������ڱ���ӷ����������������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int Add( char *inParamList[], char *strOutPut);


//Sub����
//�����������㣬��ʽstrOutPut = inParamList[0] - inParamList[1]
//inParamList(in) �ַ������������ڱ���������������������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int Sub( char *inParamList[], char *strOutPut);


//Mul����
//�����˷����㣬��ʽstrOutPut = inParamList[0] * inParamList[1]
//inParamList(in) �ַ������������ڱ���˷����������������
//strOutPut(out) ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int Mul(char *inParamList[], char *strOutPut);


//Div����
//�����������㣬��ʽstrOutPut = inParamList[0] / inParamList[1]
//inParamList(in) �ַ������������ڱ���������������������
//strOutPut(out) ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int Div(char *inParamList[], char *strOutPut);


//Rem����
//����ȡģ���㣬��ʽstrOutPut = inParamList[0] % inParamList[1]
//inParamList(in) �ַ������������ڱ���ģ������������������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int Rem(char *inParamList[], char *strOutPut);


//Cmp����
//�����Ƚ����㣬��ʽstrOutPut = inParamList[0] ?= (> or <) inParamList[1]
//inParamList(in) �ַ������������ڱ���ģ����Ķ������������
//strOutPut(out) ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int Cmp(char *inParamList[], char *strOutPut);

//Sft����
//������λ���㣬��ʽstrOutPut = inParamList[1] >>(or <<)inParamList[2]
//inParamList(in) �ַ������������ڱ���ģ������������������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int Sft(char *inParamList[], char *strOutPut);

//Gcd����
//���Լ�����㣬��ʽstrOutPut = GCD(inParamList[0] ,inParamList[1])
//inParamList(in) �ַ������������ڼ������Լ�����������������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int Gcd(char *inParamList[], char *strOutPut);


//IsPrime����
//���Լ�⣬��ʽstrOutPut = IsPrime(inParamList[0])
//inParamList(in) �ַ���������������֤���ԵĲ�����
//strOutPut(out) ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int IsPrime(char *inParamList[], char *strOutPut);


//GenPrime����
//����������
//inParamList(in) �ַ������������ڶ��������2�����������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int GenPrime(char *inParamList[], char *strOutPut);


//ModAdd����
//����ģ�����㣬��ʽstrOutPut = inParamList[0] + inParamList[1] mod inParamList[2]
//inParamList(in) �ַ�������������ģ�������3�����������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int ModAdd(char *inParamList[], char *strOutPut);


//ModSub����
//����ģ�����㣬��ʽstrOutPut = inParamList[0] - inParamList[1] mod inParamList[2]
//inParamList(in) �ַ�������������ģ�������3�����������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int ModSub(char *inParamList[], char *strOutPut);


//ModMul����
//����ģ�����㣬��ʽstrOutPut = inParamList[0] * inParamList[1] mod inParamList[2]
//inParamList(in) �ַ�������������ģ�������3�����������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int ModMul(char *inParamList[], char *strOutPut);


//ModInv����
//����ģ�����㣬��ʽstrOutPut = inParamList[0] ^ -1 mod inParamList[1]
//inParamList(in) �ַ�������������ģ�������2�����������
//strOutPut(out)         ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int ModInv(char *inParamList[], char *strOutPut);


//ModExp����
//����ģ�����㣬��ʽstrOutPut = inParamList[0] ^ inParamList[1] mod inParamList[2]
//vector<string> inParamList(in) �ַ�������������ģ�������3�����������
//string& strOutPut(out)         ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int ModExp(char *inParamList[], char *strOutPut);


//EcPointInCurve����
//�жϵ��������ϡ�
//��ʽstrOutPut = IsPointInCurve(g)
//��Բ���߷���: y^2 = x^3 + inParamList[2]x + inParamList[3] mod inParamList[4]
//inParamList(in) �ַ������������ڵ����������������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int IsPointInCurve(char *inParamList[], char *strOutPut);


//EcPointAdd����
//��Բ���ߵ��(����)���㡣
//��ʽstrOutPut = (inParamList[0],inParamList[1]) + (inParamList[2],inParamList[3])
//��Բ���߷���: y^2 = x^3 + inParamList[4]x + inParamList[5] mod inParamList[6]
//inParamList(in) �ַ������������ڵ�������7�����������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int EcPointAdd(char *inParamList[], char *strOutPut);


//EcPointMul����
//��Բ���ߵ��(������)���㡣
//��ʽstrOutPut = [inParamList[0]](inParamList[1],inParamList[2])
//��Բ���߷���: y^2 = x^3 + inParamList[3]x + inParamList[4] mod inParamList[5]
//inParamList(in) �ַ������������ڵ�������6�����������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int EcPointMul(char *inParamList[], char *strOutPut);


//EcMultPointMul����
//��Բ���߶������㡣
//��ʽstrOutPut = [inParamList[0]](inParamList[1],inParamList[2]) + [inParamList[3]](inParamList[4],inParamList[5])
//��Բ���߷���: y^2 = x^3 + inParamList[6]x + inParamList[7] mod inParamList[8]
//inParamList(in) �ַ������������ڶ��������9�����������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int EcMultPointMul(char *inParamList[], char *strOutPut);


//Rng����
//�����������
//inParamList(in) �ַ������������ڶ��������2�����������
//strOutPut(out)  ��������ַ�����ʽ�Ľ����
//������ȷ����0�����󷵻�1
int Rng(char *inParamList[], char *strOutPut);
#endif

