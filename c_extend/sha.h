#ifndef _SHA_H_
#define _SHA_H_


/*
**�� �� ��: Hash_CTX256
**����˵��: ����HASH����������Ļ����������м���������ǰ��Ҫ��ʼ����
**��    ע:   
*/
typedef struct //Hash_CTX256
{
     unsigned char      TempBuf[128];          //��ʱ����
     unsigned int     Result[8];             //������
     unsigned int     TotalLen[2];           //���������ܳ��� byte
     unsigned char      Len;                   //���һ�鳤�� byte
     unsigned char      AlgFlag;               //HASH���ͱ�־

} Hash_CTX256;

typedef struct //Hash_CTX512
{
    unsigned char      TempBuf[256];        //��ʱ����//���ǵ��������� *2
    unsigned char      Result[8][8];        //������
    unsigned int	   TotalLen[2];         //���������ܳ���  byte
    unsigned char      Len;                 //���һ�鳤�� byte
    unsigned char      AlgFlag;             //hashģʽѡ��

} Hash_CTX512;

/*
**��������: Hash_Init
**����˵��: ��ʼ��Hash���������ģ�ÿ������ǰ������á�
**����˵��: HashCtx: ָ��HASH�����Ľṹ������ָ�롣
**          Hash_mode: HASHģʽѡ�񣬰���SHA-1��SHA-224, SHA-256
**                     1 - SHA-1, 2 - SHA-244, 3 - SHA-256
**�� �� ֵ: ��
**��    ע: �� 
*/
extern unsigned char Hash_Init(Hash_CTX256 *HashCtx, unsigned char Hash_mode);


/*
**��������: Hash_Update
**����˵��: ���������Ϣ����HASH���㣬֧�ְַ����룬֧�ֿɱ䳤�ȡ�
**����˵��: HashCtx: ָ��HASH�����Ľṹ������ָ�룬ʹ��ǰ��Ҫ��ʼ����
**          Hash_DataIn: ָ����Ϣ��ַ��ָ�롣
**          InLen: ������Ϣ���ֽڳ��ȡ�
**�� �� ֵ: ��
**��    ע: ��  
*/
extern unsigned char Hash_Update(Hash_CTX256 *HashCtx, unsigned char *Hash_DataIn, unsigned int InLen);


/*
**��������: Hash_Final
**����˵��: ��������Ϣ������ɺ󣬵��ñ������õ��Ӵ�ֵ��
**����˵��: HashCtx: ָ��HASH�����Ľṹ������ָ�롣
**          Hash_DataOut: ָ���Ӵ�ֵ���յ�ַ��ָ�룬ģʽ��ͬ������ռ䲻ͬ��
**�� �� ֵ: ��
**��    ע: �� 
*/
extern unsigned char Hash_Final(Hash_CTX256 *HashCtx, unsigned char *Hash_DataOut);




/*
**��������: Hash_Final
**����˵��: ��������Ϣ������ɺ󣬵��ñ������õ��Ӵ�ֵ��
**����˵��: HashCtx: ָ��HASH�����Ľṹ������ָ�롣
**          Hash_DataOut: ָ���Ӵ�ֵ���յ�ַ��ָ�룬ģʽ��ͬ������ռ䲻ͬ��
**�� �� ֵ: ��
**��    ע: �� 
*/
extern unsigned char Hash_Final(Hash_CTX256 *HashCtx, unsigned char *Hash_DataOut);


/*
**��������: Hash_Init1
**����˵��: ��ʼ��Hash���������ģ�ÿ������ǰ������á�
**����˵��: HashCtx: ָ��HASH�����Ľṹ������ָ�롣
**          Hash_mode: HASHģʽѡ�񣬰���SHA-384��SHA-512
**                     1 - SHA-1, 2 - SHA-244, 3 - SHA-256
**�� �� ֵ: ��
**��    ע: �� 
*/
extern unsigned char Hash_Init1(Hash_CTX512 *HashCtx, unsigned char Hash_mode);

/*
**��������: Hash_Update1
**����˵��: ���������Ϣ����HASH���㣬֧�ְַ����룬֧�ֿɱ䳤�ȡ�
**����˵��: HashCtx: ָ��HASH�����Ľṹ������ָ�룬ʹ��ǰ��Ҫ��ʼ����
**          Hash_DataIn: ָ����Ϣ��ַ��ָ�롣
**          InLen: ������Ϣ���ֽڳ��ȡ�
**�� �� ֵ: ��
**��    ע: ��  
*/
extern unsigned char Hash_Update1(Hash_CTX512 *HashCtx, unsigned char *Hash_DataIn, unsigned int InLen);

/*
**��������: Hash_Final1
**����˵��: ��������Ϣ������ɺ󣬵��ñ������õ��Ӵ�ֵ��
**����˵��: HashCtx: ָ��HASH�����Ľṹ������ָ�롣
**          Hash_DataOut: ָ���Ӵ�ֵ���յ�ַ��ָ�룬ģʽ��ͬ������ռ䲻ͬ��
**�� �� ֵ: ��
**��    ע: �� 
*/
extern unsigned char Hash_Final1(Hash_CTX512 *HashCtx, unsigned char *Hash_DataOut);

#endif


