# cryptove User Guide

>> by Wei Zhang
>> <d5c5ceb0@gmail.com>

## content

   * [cryptove User Guide](#cryptove-user-guide)
      * [1. Introduction](#1-introduction)
      * [2. Overview](#2-overview)
      * [3. Cipher](#3-cipher)
         * [3.1 DES](#31-des)
            * [3.1.1 ECB](#311-ecb)
            * [3.1.2 CBC](#312-cbc)
         * [3.2 DES3](#32-des3)
            * [3.2.1 ECB](#321-ecb)
            * [3.2.2 CBC](#322-cbc)
         * [3.3 AES](#33-aes)
            * [3.3.1 ECB](#331-ecb)
            * [3.3.2 CBC](#332-cbc)
            * [3.3.3 CFB](#333-cfb)
            * [3.3.4 OFB](#334-ofb)
            * [3.3.5 CTR](#335-ctr)
            * [3.3.6 XTS](#336-xts)
         * [3.4 SM4](#34-sm4)
            * [3.4.1 ECB](#341-ecb)
            * [3.4.2 CBC](#342-cbc)
      * [4. Hash](#4-hash)
         * [4.1 MD5](#41-md5)
         * [4.2 SHA1](#42-sha1)
         * [4.3 SHA224](#43-sha224)
         * [4.4 SHA256](#44-sha256)
         * [4.5 SHA384](#45-sha384)
         * [4.6 SHA512](#46-sha512)
         * [4.7 SM3](#47-sm3)
      * [5. MAC](#5-mac)
         * [5.1 CBC-MAC](#51-cbc-mac)
            * [5.1.1 CMAC-AES](#511-cmac-aes)
            * [5.1.2 CBC-MAC-AES](#512-cbc-mac-aes)
            * [5.1.3 XCBC-MAC-AES](#513-xcbc-mac-aes)
         * [5.2 HMAC](#52-hmac)
            * [5.2.1 HMAC-MD5](#521-hmac-md5)
            * [5.2.2 HMAC-SHA1](#522-hmac-sha1)
            * [5.2.3 HMAC-SHA224](#523-hmac-sha224)
            * [5.2.4 HMAC-SHA256](#524-hmac-sha256)
            * [5.2.5 HMAC-SHA384](#525-hmac-sha384)
            * [5.2.6 HMAC-SHA512](#526-hmac-sha512)
      * [6. PK](#6-pk)
         * [6.1 BIG NUMBER](#61-big-number)
            * [6.1.1 addition](#611-addition)
            * [6.1.2 subtraction](#612-subtraction)
            * [6.1.3 multiplication](#613-multiplication)
            * [6.1.4 division](#614-division)
            * [6.1.5 remainder](#615-remainder)
            * [6.1.6 compare](#616-compare)
            * [6.1.7 or](#617-or)
            * [6.1.8 and](#618-and)
            * [6.1.9 not](#619-not)
            * [6.1.10 xor (exclusive or)](#6110-xor-exclusive-or)
            * [6.1.11 shift](#6111-shift)
            * [6.1.12 modadd (modular addition)](#6112-modadd-modular-addition)
            * [6.1.13 modsub (modular subtraction)](#6113-modsub-modular-subtraction)
            * [6.1.14 modmul (modular multiplication)](#6114-modmul-modular-multiplication)
            * [6.1.15 modinv (modular inverse)](#6115-modinv-modular-inverse)
            * [6.1.16 modexp (modular exponent)](#6116-modexp-modular-exponent)
            * [6.1.17 gcd](#6117-gcd)
            * [6.1.18 genprime](#6118-genprime)
            * [6.1.19 isprime](#6119-isprime)
            * [6.1.20 ispoint (is a ecc point)](#6120-ispoint-is-a-ecc-point)
            * [6.1.21 padd (point addition)](#6121-padd-point-addition)
            * [6.1.22 pmul (point multiplication)](#6122-pmul-point-multiplication)
            * [6.1.23 mpmul (multiple point multiplication)](#6123-mpmul-multiple-point-multiplication)
         * [6.2 RSA](#62-rsa)
            * [6.2.1 keygen](#621-keygen)
            * [6.2.2 keygen with p and q](#622-keygen-with-p-and-q)
            * [6.2.3 encription &amp; verify](#623-encription--verify)
            * [6.2.4 decryption &amp; sign](#624-decryption--sign)
            * [6.2.5 crt](#625-crt)
         * [6.3 SM2](#63-sm2)
            * [6.3.1 hash z](#631-hash-z)
            * [6.3.2 hash e](#632-hash-e)
            * [6.3.3 keygen](#633-keygen)
            * [6.3.4 sign](#634-sign)
            * [6.3.5 verify](#635-verify)
            * [6.3.6 key exchange](#636-key-exchange)
            * [6.3.7 encryption](#637-encryption)
            * [6.3.8 decryption](#638-decryption)
      * [7. random number](#7-random-number)
      * [8. CRC](#8-crc)
         * [8.1 crc16](#81-crc16)
         * [9.1 dec2hex](#91-dec2hex)
         * [9.2 endian](#92-endian)
         * [9.3 hex2bin](#93-hex2bin)
         * [9.4 bin2hex](#94-bin2hex)
         * [9.5 strsp](#95-strsp)
         * [9.7 strcat](#97-strcat)
      * [10 AEAD](#10-aead)
         * [10.1 aes_ccm (need to update)](#101-aes_ccm-need-to-update)
      * [11 ECC](#11-ecc)
         * [ecdsa_sign](#ecdsa_sign)
         * [ecdsa_verify](#ecdsa_verify)
      * [12 Stream](#12-stream)
         * [12.1 chacha20](#121-chacha20)
         * [12.2 poly1305_mac](#122-poly1305_mac)
         * [12.3 rc4](#123-rc4)



## 1. Introduction

This document describes the **cryptove** TCL API.
For further support in using this document please contact me. (Wei Zhang, d5c5ceb0@gmail.com)

## 2. Overview

The **cryptove** is a TCL library for cryptographic. Varities of cryptographic algorithms are provided (e.g. , AES, DES, HASH, HMAC, RSA, ECC, SM2, SM3, SM4, CRC, among others).

## 3. Cipher

The data can be processed in one of two modes of operation:

• Integrated operation – Processes all data in a single function call. This flow is applicable when all data is available prior to the cryptographic operation.

• Block operation – Processes a subset of the data buffers, and is called multiple times in a sequence. This flow is applicable when the next data buffer becomes available only during/after processing of the current data buffer.

### 3.1 DES

DES is a block cipher, i.e. it processes data in multiples of block size (8 bytes), and the key size is 8 bytes too.

#### 3.1.1 ECB

* Integrated operation:

**COMMAND:**

```
des_ecb_process direction key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  DES key of 8 bytes                         |
|messages  |  data, multiples of 8 bytes                 |

**EXAMPLE:**

```
set K bbe07cd54390e120
set M ff50228ae7c3799ad8eea7c053d6bb0d8814a9bf89a6b1b62b485adb8765f60b
des_ecb_process enc $K $M
#the result is 910e28d0543dbf02ba46a430f8e1a0148cd7764d66f8ea3b986244dfc2e0d9bb
```

* Block operation:

**COMMAND:**

```
des_ecb_init   ctx direction key
des_ecb_update ctx messages
des_ecb_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  DES key of 8 bytes                         |
|messages  |  data, multiples of 8 bytes                 |

**example:**

```
set K  bbe07cd54390e120
set M1 ff50228ae7c3799a
set M2 d8eea7c053d6bb0d8814a9bf89a6b1b6
set M3 2b485adb8765f60b
des_ecb_init   ecb_ctx enc $K
des_ecb_update ecb_ctx $M1
des_ecb_update ecb_ctx $M2
des_ecb_update ecb_ctx $M3
des_ecb_done   ecb_ctx
#the result is 910e28d0543dbf02ba46a430f8e1a0148cd7764d66f8ea3b986244dfc2e0d9bb
```


#### 3.1.2 CBC

* Integrated operation:

**COMMAND:**

```
des_cbc_process direction key iv messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  DES key of 8 bytes                         |
|iv        |  iv                                         |
|messages  |  data, multiples of 8 bytes                 |

**example:**

```
set K 75168e70130b9f7b
set IV 6c2fb0fa6a39073c
set M ff50228ae7c3799ad8eea7c053d6bb0d8814a9bf89a6b1b62b485adb8765f60b
des_cbc_process enc $K $IV $M
#result d6fdb31e2cdb5d27a68a90cc88e9d30230b2fe8f6f49f352ba694cbdcb01f8ef
```

* Block operation:

**COMMAND:**

```
des_cbc_init   ctx direction key iv
des_cbc_update ctx messages
des_cbc_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  DES key of 8 bytes                         |
|iv        |  iv                                         |
|messages  |  data, multiples of 8 bytes                 |

**EXAMPLE:**

```
set K  75168e70130b9f7b
set IV 6c2fb0fa6a39073c
set M1 ff50228ae7c3799a
set M2 d8eea7c053d6bb0d8814a9bf89a6b1b6
set M3 2b485adb8765f60b
des_cbc_init   cbc_ctx enc $K $IV
des_cbc_update cbc_ctx $M1
des_cbc_update cbc_ctx $M2
des_cbc_update cbc_ctx $M3
des_cbc_done   cbc_ctx
#result is d6fdb31e2cdb5d27a68a90cc88e9d30230b2fe8f6f49f352ba694cbdcb01f8ef
```

### 3.2 DES3

#### 3.2.1 ECB

* Integrated operation:


**COMMAND:**

```
des3_ecb_process direction key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes or 24 bytes)                  |
|messages  |  data, multiples of 8 bytes                 |

**EXAMPLE:**

```
set K1 6a0cb7b06ddf5aca
set K2 3e914852e5afc9a4
set M ff50228ae7c3799ad8eea7c053d6bb0d8814a9bf89a6b1b62b485adb8765f60b
des3_ecb_process enc ${K1}$K2 $M
#the result is bc80a40bd8d22961f16a2ecd5e4c3ed0afdbfd37b7ca18df6e82798c3574bcb9
```

* Block operation:

**COMMAND:**

```
des3_ecb_init   ctx direction key
des3_ecb_update ctx messages
des3_ecb_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes or 24 bytes)                  |
|messages  |  data, multiples of 8 bytes                 |

**EXAMPLE:**

```
set K1 6a0cb7b06ddf5aca
set K2 3e914852e5afc9a4
set M1 ff50228ae7c3799a
set M2 d8eea7c053d6bb0d8814a9bf89a6b1b6
set M3 2b485adb8765f60b
des3_ecb_init   ecb_ctx enc ${K1}$K2
des3_ecb_update ecb_ctx $M1
des3_ecb_update ecb_ctx $M2
des3_ecb_update ecb_ctx $M3
des3_ecb_done   ecb_ctx
#the result is bc80a40bd8d22961f16a2ecd5e4c3ed0afdbfd37b7ca18df6e82798c3574bcb9
```

#### 3.2.2 CBC

* Integrated operation:

**COMMAND:**

```
des3_cbc_process direction key iv messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key (16 bytes, or 24 bytes)                |
|iv        |  iv                                         |
|messages  |  data, multiples of 8 bytes                 |

**EXAMPLE:**

```
set K1 6a0cb7b06ddf5aca
set K2 3e914852e5afc9a4
set IV 6c2fb0fa6a39073c
set M ff50228ae7c3799ad8eea7c053d6bb0d8814a9bf89a6b1b62b485adb8765f60b
des3_cbc_process enc ${K1}${K2} $IV $M
#the result is 15e40b8bf0ab86caac5a6b9178a94ce41836e1b7e7d9bdd54f26a29ac581d0a0
```

* Block operation:

**COMMAND:**

```
des_cbc_init  ctx direction key iv
des_cbc_update  ctx messages
des_cbc_done ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key (16 bytes, or 24 bytes)                |
|iv        |  iv                                         |
|messages  |  data, multiples of 8 bytes                 |

**EXAMPLE:**

```
set K1 6a0cb7b06ddf5aca
set K2 3e914852e5afc9a4
set IV 6c2fb0fa6a39073c
set M1 ff50228ae7c3799a
set M2 d8eea7c053d6bb0d8814a9bf89a6b1b6
set M3 2b485adb8765f60b
des3_cbc_init   cbc_ctx enc ${K1}${K2} $IV
des3_cbc_update cbc_ctx $M1
des3_cbc_update cbc_ctx $M2
des3_cbc_update cbc_ctx $M3
des3_cbc_done   cbc_ctx
#result is 15e40b8bf0ab86caac5a6b9178a94ce41836e1b7e7d9bdd54f26a29ac581d0a0
```

### 3.3 AES

#### 3.3.1 ECB

* Integrated operation:


**COMMAND:**

```
aes_ecb_process direction key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 16124AD88976E46BEA7B25F52F9DBDBD59C436C635B3CE9E61ED4C9857CB7D5B
set M 63CDB50D8D7439459DA8288231B154F5
aes_ecb_process enc $K $M
#the result is 83e7b2981c148a46afb34278c033623f
```

* Block operation:

**COMMAND:**

```
aes_ecb_init   ctx direction key
aes_ecb_update ctx messages
aes_ecb_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|messages  |  data, multiples of 16 bytes                |


**EXAMPLE:**

```
set K 16124AD88976E46BEA7B25F52F9DBDBD59C436C635B3CE9E61ED4C9857CB7D5B
set M 63CDB50D8D7439459DA8288231B154F5
aes_ecb_init   ecb_ctx enc $K $IV
aes_ecb_update ecb_ctx $M
aes_ecb_done   ecb_ctx
#the result is 83e7b2981c148a46afb34278c033623f
```

#### 3.3.2 CBC

* Integrated operation:


**COMMAND:**

```
aes_cbc_process direction key iv messages
```


|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |


**EXAMPLE:**

```
set K 16124AD88976E46BEA7B25F52F9DBDBD59C436C635B3CE9E61ED4C9857CB7D5B
set IV E6490D022F79FB8CB3EFEEAED923E6E2
set M 7C5295B0E79D37C9B67FA572CBE304FD538A1D169E24DF1F3B11A3AF5D1335531C322D700128160ED8A0BDE2A57FA3DD
aes_cbc_process enc $K $IV $M
#the result is 2c8e43749486350ef1178500325dc5f69a73eb2c0222815bff5b91d122849f4f60394e405c12603f3d70b8f10cd4af75
```

* Block operation:

**COMMAND:**

```
aes_cbc_init   ctx direction key iv
aes_cbc_update ctx messages
aes_cbc_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 16124AD88976E46BEA7B25F52F9DBDBD59C436C635B3CE9E61ED4C9857CB7D5B
set IV E6490D022F79FB8CB3EFEEAED923E6E2
set M 7C5295B0E79D37C9B67FA572CBE304FD538A1D169E24DF1F3B11A3AF5D1335531C322D700128160ED8A0BDE2A57FA3DD
aes_cbc_init   cbc_ctx enc $K $IV
aes_cbc_update cbc_ctx $M
aes_cbc_done   cbc_ctx
#the result is 2c8e43749486350ef1178500325dc5f69a73eb2c0222815bff5b91d122849f4f60394e405c12603f3d70b8f10cd4af75
```

#### 3.3.3 CFB

* Integrated operation:

**COMMAND:**

```
aes_cfb_process direction key iv messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 2b7e151628aed2a6abf7158809cf4f3c
set IV 000102030405060708090a0b0c0d0e0f
set M 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
aes_cfb_process enc $K $IV $M
#the result is 3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6
```

* Block operation:


**COMMAND:**

```
aes_cfb_init   ctx direction key iv
aes_cfb_update ctx messages
aes_cfb_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 2b7e151628aed2a6abf7158809cf4f3c
set IV 000102030405060708090a0b0c0d0e0f
set M 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
aes_cfb_init   cfb_ctx enc $K $IV
aes_cfb_update cfb_ctx $M
aes_cfb_done   cfb_ctx
#the result is 3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6
```

#### 3.3.4 OFB

* Integrated operation:


**COMMAND:**

```
aes_ofb_process direction key iv messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |


**EXAMPLE:**

```
set K 2b7e151628aed2a6abf7158809cf4f3c
set IV 000102030405060708090a0b0c0d0e0f
set M 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
aes_ofb_process enc $K $IV $M
#the result is 3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e
```

* Block operation:

**COMMAND:**

```
aes_ofb_init   ctx direction key iv
aes_ofb_update ctx messages
aes_ofb_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 2b7e151628aed2a6abf7158809cf4f3c
set IV 000102030405060708090a0b0c0d0e0f
set M 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
aes_ofb_init   ofb_ctx enc $K $IV
aes_ofb_update ofb_ctx $M
aes_ofb_done   ofb_ctx
#the result is 3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e
```

#### 3.3.5 CTR

* Integrated operation:


**COMMAND:**

```
aes_ctr_process direction key iv messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |


**EXAMPLE:**

```
set K 2b7e151628aed2a6abf7158809cf4f3c
set IV f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
set M 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
aes_ctr_process enc $K $IV $M
#the result is 874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee
```

* Block operation:


**COMMAND:**

```
aes_ctr_init   ctx direction key iv
aes_ctr_update ctx messages
aes_ctr_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 2b7e151628aed2a6abf7158809cf4f3c
set IV f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
set M 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
aes_ctr_init   ctr_ctx enc $K $IV
aes_ctr_update ctr_ctx $M
aes_ctr_done   ctr_ctx
#the result is 874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee
```

#### 3.3.6 XTS

* Integrated operation:

**COMMAND:**

```
aes_xts_process direction key iv messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes or 32 bytes)                  |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |


**EXAMPLE:**

```
set K1  fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0
set K2 22222222222222222222222222222222
set IV 33333333330000000000000000000000
set M 4444444444444444444444444444444444444444444444444444444444444444
aes_xts_process enc ${K1}${K2} $IV $M
#the result is af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89
```

* Block operation:

**COMMAND:**

```
aes_xts_init   ctx direction key iv
aes_xts_update ctx messages
aes_xts_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes or 32 bytes)                  |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K1  fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0
set K2 22222222222222222222222222222222
set IV 33333333330000000000000000000000
set M 4444444444444444444444444444444444444444444444444444444444444444
aes_xts_init   xts_ctx enc ${K1}${K2} $IV
aes_xts_update xts_ctx $M
aes_xts_done   xts_ctx
#the result is af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89
```

### 3.4 SM4

#### 3.4.1 ECB

* Integrated operation:

**COMMAND:**

```
sm4_ecb_process direction key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes)                              |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 0123456789abcdeffedcba9876543210
set M 0123456789abcdeffedcba9876543210
sm4_ecb_process enc $K $M
#the result is 681edf34d206965e86b3e94f536e4246
```

* Block operation:

**COMMAND:**

```
sm4_ecb_init   ctx direction key
sm4_ecb_update ctx messages
sm4_ecb_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes)                              |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 0123456789abcdeffedcba9876543210
set M 0123456789abcdeffedcba9876543210
sm4_ecb_init   ecb_ctx enc $K $IV
sm4_ecb_update ecb_ctx $M
sm4_ecb_done   ecb_ctx
#the result is 681edf34d206965e86b3e94f536e4246
```

#### 3.4.2 CBC

* Integrated operation:

**COMMAND:**

```
sm4_cbc_process direction key iv messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes)                              |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 0123456789abcdeffedcba9876543210
set IV 0123456789abcdeffedcba9876543210
set M 131817B709047289284435032A988A7872198601F6066B6B077A97059C5D6792A8F75FF136A71FAA7D745322D75277B4
sm4_cbc_process enc $K $IV $M
#the result is 51e58110754e112683f90c4fea97cfd6cf17ce2fbb6292ee9f549f7fbd589e161a352cc7a523c4cdeb00fdca4cf49c3d
```

* Block operation:

**COMMAND:**

```
sm4_cbc_init   ctx direction key iv
aes_cbc_update ctx messages
aes_cbc_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|direction |  “enc” for encryption; “dec” for decryption |
|key       |  key(16 bytes)                              |
|iv        |  iv                                         |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 0123456789abcdeffedcba9876543210
set IV 0123456789abcdeffedcba9876543210
set M 131817B709047289284435032A988A7872198601F6066B6B077A97059C5D6792A8F75FF136A71FAA7D745322D75277B4
sm4_cbc_init   cbc_ctx enc $K $IV
sm4_cbc_update cbc_ctx $M
sm4_cbc_done   cbc_ctx
#the result is 51e58110754e112683f90c4fea97cfd6cf17ce2fbb6292ee9f549f7fbd589e161a352cc7a523c4cdeb00fdca4cf49c3d
```

## 4. Hash

The data can be processed in one of two modes of operation:

• Integrated operation – Processes all data in a single function call. This flow is applicable when all data is available prior to the cryptographic operation.

• Block operation – Processes a subset of the data buffers, and is called multiple times in a sequence. This flow is applicable when the next data buffer becomes available only during/after processing of the current data buffer.

### 4.1 MD5

* Integrated operation:

**COMMAND:**

```
md5_process  messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|messages  |  data                                       |


**EXAMPLE:**
```
set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
md5_process $message
#the result is b3eb9ac023b813857b895dd3cc74ec11
```

* Block operation:

**COMMAND:**

```
md5_init   ctx
md5_update ctx messages
md5_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|messages  |  data                                       |

**EXAMPLE:**

```
set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
md5_init   md5_ctx
md5_update md5_ctx $message
md5_done   md5_ctx
#the result is b3eb9ac023b813857b895dd3cc74ec11
```

### 4.2 SHA1

* Integrated operation:

**COMMAND:**

```
sha1_process  messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|messages  |  data                                       |

**EXAMPLE:**

```
set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
sha1_process $message
#the result is cae74849fc4ca9ae98ce22db01d0561beaa47bd6
```

* Block operation:

**COMMAND:**

```
sha1_init   ctx 
sha1_update ctx messages
sha1_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|messages  |  data                                       |

**EXAMPLE:**
```
set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
sha1_init   sha1_ctx
sha1_update sha1_ctx $message
sha1_done   sha1_ctx
#the result is cae74849fc4ca9ae98ce22db01d0561beaa47bd6
```

### 4.3 SHA224

* Integrated operation:

**COMMAND:**
```
sha224_process  messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|messages  |  data                                       |

**EXAMPLE:**

```
set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
sha224_process $message
#the result is 2234ac071a938111cb1cb79e054b548a80206cb38e0a038a565a3a05
```

* Block operation:

**COMMAND:**

```
sha224_init   ctx
sha224_update ctx messages
sha224_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|messages  |  data                                       |

**EXAMPLE:**

```
set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
sha224_init   sha224_ctx
sha224_update sha224_ctx $message
sha224_done   sha224_ctx
#the result is 2234ac071a938111cb1cb79e054b548a80206cb38e0a038a565a3a05
```

### 4.4 SHA256

* Integrated operation:

**COMMAND:**

```
sha256_process  messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|messages  |  data                                       |

**EXAMPLE:**

```
set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
sha256_process $message
#the result is af9f0cb3809944ba914dd2d28721c6f03956911f4450e481cb18ff9f92efdc65
```

* Block operation:

**COMMAND:**

```
sha256_init   ctx
sha256_update ctx messages
sha256_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|messages  |  data                                       |

**EXAMPLE:**

```
set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
sha256_init   sha256_ctx
sha256_update sha256_ctx $message
sha256_done   sha256_ctx
#the result is af9f0cb3809944ba914dd2d28721c6f03956911f4450e481cb18ff9f92efdc65
```

### 4.5 SHA384

* Integrated operation:

**COMMAND:**

```
sha384_process  messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|messages  |  data                                       |

**EXAMPLE:**

```
set message 4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c
sha384_process $message
#the result is d31114cf0abc09647b4737df418ea09d692054f0a10048a05d765e30398409597e4f6d1d83bff919f2584bd15a138430
```

* Block operation:

**COMMAND:**

```
sha384_init   ctx
sha384_update ctx messages
sha384_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|messages  |  data                                       |

**EXAMPLE:**

```
set message 4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c
sha384_init   sha384_ctx
sha384_update sha384_ctx $message
sha384_done   sha384_ctx
#the result is d31114cf0abc09647b4737df418ea09d692054f0a10048a05d765e30398409597e4f6d1d83bff919f2584bd15a138430
```

### 4.6 SHA512

* Integrated operation:

**COMMAND:**

```
sha512_process  messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|messages  |  data                                       |

**EXAMPLE:**

```
set message 4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c
sha512_process $message
#the result is 9bc1660a879982f04edee7fefab921f1e6e5fc7078023a0dd251987b6fcdbe9e7521a73e652b3e1ba4eb683d3967e39e37d21b057645b411b71efd461d3594fb
```

* Block operation:

**COMMAND:**

```
sha512_init   ctx
sha512_update ctx messages
sha512_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|messages  |  data                                       |

**EXAMPLE:**

```
set message 4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c
sha512_init   sha512_ctx
sha512_update sha512_ctx $message
sha512_done   sha512_ctx
#the result is 9bc1660a879982f04edee7fefab921f1e6e5fc7078023a0dd251987b6fcdbe9e7521a73e652b3e1ba4eb683d3967e39e37d21b057645b411b71efd461d3594fb
```

### 4.7 SM3

* Integrated operation:

**COMMAND:**

```
sm3_process  messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|messages  |  data                                       |

**EXAMPLE:**

```
set message 1e
sm3_process $message
#the result is 83cf37260488edcb9cee59f9777e0cc613d6c70e5a55cf4318fcde04815a08bd
```

* Block operation:

**COMMAND:**

```
sm3_init   ctx
sm3_update ctx messages
sm3_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|messages  |  data                                       |

**EXAMPLE:**

```
set message 1e
sm3_init   sm3_ctx
sm3_update sm3_ctx $message
sm3_done   sm3_ctx
#the result is 83cf37260488edcb9cee59f9777e0cc613d6c70e5a55cf4318fcde04815a08bd
```

## 5. MAC

The data can be processed in one of two modes of operation:

• Integrated operation – Processes all data in a single function call. This flow is applicable when all data is available prior to the cryptographic operation.

• Block operation – Processes a subset of the data buffers, and is called multiple times in a sequence. This flow is applicable when the next data buffer becomes available only during/after processing of the current data buffer.

### 5.1 CBC-MAC

#### 5.1.1 CMAC-AES

* Integrated operation:

**COMMAND:**

```
aes_cmac_process key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 2b7e151628aed2a6abf7158809cf4f3c
set M 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411
aes_cmac_process $K $M
#the result is dfa66747de9ae63030ca32611497c827
```

* Block operation:

**COMMAND:**

```
aes_cmac_init   ctx key
aes_cmac_update ctx messages
aes_cmac_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 2b7e151628aed2a6abf7158809cf4f3c
set M 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411
aes_cmac_init   cmac_ctx $K
aes_cmac_update cmac_ctx $M
aes_cmac_done   cmac_ctx
#the result is dfa66747de9ae63030ca32611497c827
```

#### 5.1.2 CBC-MAC-AES

* Integrated operation:

**COMMAND:**

```
aes_cbcmac_process key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 2b7e151628aed2a6abf7158809cf4f3c
set M 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
aes_cbcmac_process $K $M
#the result is a7356e1207bb406639e5e5ceb9a9ed93
```

* Block operation:

**COMMAND:**

```
aes_cbcmac_init   ctx key
aes_cbcmac_update ctx messages
aes_cbcmac_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|key       |  key(16 bytes, 24 bytes or 32 bytes)        |
|messages  |  data, multiples of 16 bytes                |

**EXAMPLE:**

```
set K 2b7e151628aed2a6abf7158809cf4f3c
set M 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
aes_cbcmac_init   cbcmac_ctx $K
aes_cbcmac_update cbcmac_ctx $M
aes_cbcmac_done   cbcmac_ctx
#the result is a7356e1207bb406639e5e5ceb9a9ed93
```

#### 5.1.3 XCBC-MAC-AES

* Integrated operation:

**COMMAND:**

```
aes_xcbcmac_process key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|key       |  key(16 bytes)                              |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 000102030405060708090a0b0c0d0e0f
set M 000102
aes_xcbcmac_process $K $M
#the result is 5b376580ae2f19afe7219ceef172756f
```

* Block operation:

**COMMAND:**

```
aes_xcbcmac_init   ctx key
aes_xcbcmac_update ctx messages
aes_xcbcmac_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|key       |  key(16 bytes)                              |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 000102030405060708090a0b0c0d0e0f
set M 000102
aes_xcbcmac_init   xcbcmac_ctx $K
aes_xcbcmac_update xcbcmac_ctx $M
aes_xcbcmac_done   xcbcmac_ctx
#the result is 5b376580ae2f19afe7219ceef172756f
```

### 5.2 HMAC

#### 5.2.1 HMAC-MD5

* Integrated operation:

**COMMAND:**

```
md5_hmac_process key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
md5_hmac_process $K $M
#the result is 3ba82db082e75093203ff41d9f4f6d52
```

* Block operation:

**COMMAND:**

```
md5_hmac_init   ctx key
md5_hmac_update ctx messages
md5_hmac_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
md5_hmac_init   hmac_ctx $K
md5_hmac_update hmac_ctx $M
md5_hmac_done   hmac_ctx
#the result is 3ba82db082e75093203ff41d9f4f6d52
```

#### 5.2.2 HMAC-SHA1

* Integrated operation:

**COMMAND:**

```
sha1_hmac_process key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
sha1_hmac_process $K $M
#the result is 0d232f31b745171451e97fe73e9c307d9d5555bd
```

* Block operation:

**COMMAND:**

```
sha1_hmac_init   ctx key
sha1_hmac_update ctx messages
sha1_hmac_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
sha1_hmac_init   hmac_ctx $K
sha1_hmac_update hmac_ctx $M
sha1_hmac_done   hmac_ctx
#the result is 0d232f31b745171451e97fe73e9c307d9d5555bd
```

#### 5.2.3 HMAC-SHA224

* Integrated operation:

**COMMAND:**

```
sha224_hmac_process key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
sha224_hmac_process $K $M
#the result is 13e71b85772ec123d2614870072c2330f70bd2c8f7973d27b032825b
```

* Block operation:

**COMMAND:**

```
sha224_hmac_init   ctx key
sha224_hmac_update ctx messages
sha224_hmac_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
sha224_hmac_init   hmac_ctx $K
sha224_hmac_update hmac_ctx $M
sha224_hmac_done   hmac_ctx
#the result is 13e71b85772ec123d2614870072c2330f70bd2c8f7973d27b032825b
```

#### 5.2.4 HMAC-SHA256

* Integrated operation:

**COMMAND:**

```
sha256_hmac_process key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
sha256_hmac_process $K $M
#the result is 3c0b856e96f74d7f74d1f8e8838456dadcfc85dc34403c7f0ddc168108c2ce13
```

* Block operation:

**COMMAND:**

```
sha256_hmac_init   ctx key
sha256_hmac_update ctx messages
sha256_hmac_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
sha256_hmac_init   hmac_ctx $K
sha256_hmac_update hmac_ctx $M
sha256_hmac_done   hmac_ctx
#the result is 3c0b856e96f74d7f74d1f8e8838456dadcfc85dc34403c7f0ddc168108c2ce13
```

#### 5.2.5 HMAC-SHA384

* Integrated operation:

**COMMAND:**

```
sha384_hmac_process key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
sha384_hmac_process $K $M
#the result is e685fa4ea7efd11b2d583cd7f035fded03612316083df1e6659266d5514a0b7a9f4e9af505c567501e1a8bbca16435f9
```

* Block operation:

**COMMAND:**

```
sha384_hmac_init   ctx key
sha384_hmac_update ctx messages
sha384_hmac_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
sha384_hmac_init   hmac_ctx $K
sha384_hmac_update hmac_ctx $M
sha384_hmac_done   hmac_ctx
#the result is e685fa4ea7efd11b2d583cd7f035fded03612316083df1e6659266d5514a0b7a9f4e9af505c567501e1a8bbca16435f9
```

#### 5.2.6 HMAC-SHA512

* Integrated operation:

**COMMAND:**

```
sha512_hmac_process key messages
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
sha512_hmac_process $K $M
#the result is 24e74026d857f6f4b9ac8e645f0753755e4895235e71a7833ff2c7c29b2cd3c9b3494b02fea0e43a91a3a8cd1970734d4172f058309f099331929153facebff8
```

* Block operation:

**COMMAND:**

```
sha512_hmac_init   ctx key
sha512_hmac_update ctx messages
sha512_hmac_done   ctx
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ctx       |  the context of this session                |
|key       |  key                                        |
|messages  |  data                                       |

**EXAMPLE:**

```
set K 41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
set M 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
sha512_hmac_init   hmac_ctx $K
sha512_hmac_update hmac_ctx $M
sha512_hmac_done   hmac_ctx
#the result is 24e74026d857f6f4b9ac8e645f0753755e4895235e71a7833ff2c7c29b2cd3c9b3494b02fea0e43a91a3a8cd1970734d4172f058309f099331929153facebff8
```

## 6. PK

### 6.1 BIG NUMBER

#### 6.1.1 addition

**COMMAND:**

```
add a b

prototype:
result = a + b
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |

**EXAMPLE:**

```
add 01 0102
#the result is 0103
```

#### 6.1.2 subtraction

**COMMAND:**

```
sub a b

prototype:
result = a – b
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |

**EXAMPLE:**

```
sub  0403 0102
#the result is 0301
```

#### 6.1.3 multiplication

**COMMAND:**

```
mul a b

prototype:
result = a * b
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |

**EXAMPLE:**

```
mul ff ff
#the result is FE01
```

#### 6.1.4 division

**COMMAND:**

```
div a b

prototype:
result = a / b
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |

**EXAMPLE:**

```
div 10 04
#the result is 04
```

#### 6.1.5 remainder

**COMMAND:**

```
rem a b

prototype:
result = a % b
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |

**EXAMPLE:**

```
rem 10 07
#the result is 02
```

#### 6.1.6 compare

**COMMAND:**

```
cmp a b

prototype:
result = a compare with b
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |

|ret | descrption     |
|----|----------------|
|00  |a equal to b    |
|01  |a larger than b |
|02  |a smaller than b|

**EXAMPLE:**

```
cmp FFFFFFFFFF AFFFFFFFFF
#the result is 01
```

#### 6.1.7 or

**COMMAND:**

```
orr a b

prototype:
result = a | b
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |

**EXAMPLE:**

```
orr 0f0f0f0f f0f0f0f0
#the result is  ffffffff
```

#### 6.1.8 and

**COMMAND:**

```
and a b

prototype:
result = a & b
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |

**EXAMPLE:**

```
and 0f0f0f0f f0f0f0f0
#the result is  00000000
```

#### 6.1.9 not

**COMMAND:**

```
not a

prototype:
result = ~a
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |

**EXAMPLE:**

```
not 0f0f0f0f
#the result is  f0f0f0f0
```

#### 6.1.10 xor (exclusive or)

**COMMAND:**

```
xor a b

prototype:
result = a ^ b
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |

**EXAMPLE:**

```
xor 0f0f0f0f  0f0f0f0f
#the result is  00000000
```

#### 6.1.11 shift

**COMMAND:**

```
sft mode x n

prototype:
result = sftmode(x, n)
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|mode      | R – shift right; L – shift left             |
|x         | argument a in Hexadecimal                   |
|n         | shift n bits                                |

**EXAMPLE:**

```
sft R FFFFFFFFFF 4
#the result is  0FFFFFFFFF
```

#### 6.1.12 modadd (modular addition)

**COMMAND:**

```
modadd a b n

prototype:
result = (a+b) % n
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |
|n         | argument n in Hexadecimal                   |

**EXAMPLE:**

```
modadd 07 09 0F
#the result is  01
```

#### 6.1.13 modsub (modular subtraction)

**COMMAND:**

```
modsub a b n

prototype:
result = (a+b) % n
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |
|n         | argument n in Hexadecimal                   |

**EXAMPLE:**

```
modsub 07 09 0F
#the result is  0D
```

#### 6.1.14 modmul (modular multiplication)

**COMMAND:**

```
modmul a b n

prototype:
result = (a*b) % n
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |
|n         | argument n in Hexadecimal                   |

**EXAMPLE:**

```
modmul 07 09 0F
#the result is  03
```

#### 6.1.15 modinv (modular inverse)

**COMMAND:**

```
modinv a n

prototype:
result = a^-1 % n
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|n         | argument n in Hexadecimal                   |

**EXAMPLE:**

```
modinv 07 0F
#the result is  0d
```

#### 6.1.16 modexp (modular exponent)

**COMMAND:**

```
modexp a b n

prototype:
result = (a**b) % n
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |
|n         | argument n in Hexadecimal                   |

**EXAMPLE:**

```
modexp 08 07 0F
#the result is  02
```

#### 6.1.17 gcd

**COMMAND:**

```
gcd a b

prototype:
result = gcd(a,b)
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |
|b         | argument b in Hexadecimal                   |

**EXAMPLE:**

```
gcd 10 08
#the result is  08
```

#### 6.1.18 genprime

**COMMAND:**

```
genprime a

prototype:
result = genprime(a), and result > a
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |

example:

```
genprime 09
#the result is  0B
```

#### 6.1.19 isprime

**COMMAND:**

```
isprime a

prototype:
result = isprime(a)

01- prime，00-not prime
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|a         | argument a in Hexadecimal                   |

**EXAMPLE:**

```
isprime 0B
#the result is  01
```

#### 6.1.20 ispoint (is a ecc point)

**COMMAND:**

```
ispoint  (Px||Py)  (p||a||b)

```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|PxPy      | the point (Px, Py) in curve                 |
|pab       | the parameters of curve                     |

|ret | descrption     |
|----|----------------|
|00  | not a point    |
|01  | is a point     |

**EXAMPLE:**

```
ispoint 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0 FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
#the result is  01
```

#### 6.1.21 padd (point addition)

**COMMAND:**

```
padd  (Pax||Pay)  (Pbx||Pby)  (P||A||B)

prototype:
result = add(Pa, pb)   ( may be Pa is equal to Pb)
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|PaxPay    | the point (Pax, Pay) in curve               |
|PbxPby    | the point (Pbx, Pby) in curve               |
|pab       | the parameters of curve                     |

**EXAMPLE:**

```
padd 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0  CD459EA427E560E014F420F502055A20471AAE6B97CD5B66F01D87BAB250138B41DA65A7C7058F965EF911D6F5E45B536626DDE93E687C085EB506DC94BEDF79 FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93

#the result is  A2AC8E7C46DA9BCF17B4B7D41E9EB95F6B2746FCC162DF217523554D6599488A8DD6719817138AFCDF67FF521AAE15B8FB6D9A3F53982B3DC2C1E81F63EADFB3
```

#### 6.1.22 pmul (point multiplication)

**COMMAND:**

```
pmul k  (Px||Py)  (p||a||b)

prototype:
result = [k]*P
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|k         | scalar number                               |
|PxPy      | the point (Px, Py) in curve                 |
|(pab)     | the parameters of curve                     |

**EXAMPLE:**

```
pmul D84DC07A8426395E0CE43AEA82DB9ACCF2568D0F2D63772D9897D1334D1F20C3 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0 FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
#the result is CD459EA427E560E014F420F502055A20471AAE6B97CD5B66F01D87BAB250138B41DA65A7C7058F965EF911D6F5E45B536626DDE93E687C085EB506DC94BEDF79
```

#### 6.1.23 mpmul (multiple point multiplication)

**COMMAND:**

```
mpmul  k  (Px||Py)  k2  (P2x||P2y)  (p||a||b)

prototype:
result =  [k](Pax||Pay) + [k2](P2x||P2y)
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|k         | scalar number                               |
|k2        | scalar number                               |
|PxPy      | the point (Px, Py) in curve                 |
|P2xP2y    | the point (P2x, P2y) in curve               |
|(pab)     | the parameters of curve                     |

**EXAMPLE:**

```
mpmul 3538D6F877B83AB3C9E298BBA7459C9629B533281A5A823EAC601DE8CFF5A0CB 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0 8890058758226876DBD0231C2F2C3D7D4641760B7B0B8D944493B57F1F3A8DCA CD459EA427E560E014F420F502055A20471AAE6B97CD5B66F01D87BAB250138B41DA65A7C7058F965EF911D6F5E45B536626DDE93E687C085EB506DC94BEDF79 FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93

#the result is D6D2FD1E1950EAA66A5B6F91AE90ECDF2E839A3EEAA4F859F7B7561F3749630135AF9B85C8A3DD09521438D922B68F08E79819E4B11C1E0315D8134AB13D3139
```

### 6.2 RSA

#### 6.2.1 keygen

**COMMAND:**

```
rsa_keygen e nlen
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|e         | public key                                  |
|nlen      | byte len of modulus n                       |

|return code|
|-----------|
|{e n d p q dp dq qinv}|

**EXAMPLE:**
```
rsa_keygen 010001 64

#the result is 
#010001 #89DEDAA0746C2259DD5767A20C6BE19C411A346F1C51A9F2F5BD32B3A679B08E52DF5DFACA79605A57C10861BC8D14B1B6879EEA3EC585389D2483D3FFB276BD #1C4479F4DE09F1BD1519BFA0C505357BB1096B68C098A9CCABBFBFEE7F9A81AD4E62F0A4FC1D4846B7D46CEEB527EFBB5986EC63CAAF2411A4F22682EFE1794D #9D37127EA963C39ECAD6377EC2F2CCFA213471737A943D4B766FBEA8B78E3BF3 #E08018465E942A97C4DEAF382C5D16718B2F220EAA60E5738AF6039E93859E8F #06C4691A64A633B4711CB974CE656F27512895BD97C82BBF44D0D88F209F91BB #616450A39E7E2AA82298F46CAB1A4B1540EB569C041FFB0A8FFB4000B840DC53 #82AD5A6EEA786CCA74F62C0646D38AA11E1AFEBA8E659F43C53C034EB538FC75
```

#### 6.2.2 keygen with p and q

**COMMAND:**

```
rsa_keygen_pq e p q
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|e         | public key                                  |
|p         | the first prime number                      |
|q         | the second prime number                     |

**EXAMPLE:**

```
set p 9D37127EA963C39ECAD6377EC2F2CCFA213471737A943D4B766FBEA8B78E3BF3 
set q E08018465E942A97C4DEAF382C5D16718B2F220EAA60E5738AF6039E93859E8F
rsa_keygen_pq 010001 $p $q

#the result is 
#010001 #89DEDAA0746C2259DD5767A20C6BE19C411A346F1C51A9F2F5BD32B3A679B08E52DF5DFACA79605A57C10861BC8D14B1B6879EEA3EC585389D2483D3FFB276BD #1C4479F4DE09F1BD1519BFA0C505357BB1096B68C098A9CCABBFBFEE7F9A81AD4E62F0A4FC1D4846B7D46CEEB527EFBB5986EC63CAAF2411A4F22682EFE1794D #9D37127EA963C39ECAD6377EC2F2CCFA213471737A943D4B766FBEA8B78E3BF3 #E08018465E942A97C4DEAF382C5D16718B2F220EAA60E5738AF6039E93859E8F #06C4691A64A633B4711CB974CE656F27512895BD97C82BBF44D0D88F209F91BB #616450A39E7E2AA82298F46CAB1A4B1540EB569C041FFB0A8FFB4000B840DC53 #82AD5A6EEA786CCA74F62C0646D38AA11E1AFEBA8E659F43C53C034EB538FC75
```

#### 6.2.3 encription & verify

**COMMAND:**

```
rsa_enc e n M
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|e         | public key                                  |
|n         | modulus                                     |
|M         | messages                                    |

**EXAMPLE:**

```
set e 010001
set n AE98622E42C289499D28B88FAA3007C671111D448FF3B449D35D2C6999CE2C830BDAD6C38BA1AB356E227B3D626A5EB5716C1A1C319A00F7F2909FDBCA3CAECF
set M A6A1E0F26DDCE4D2512010256D3431F77EE9EA99091A7AB30AFB1DEC1B52DEBF0DF420AAB94CC9E50253309B308011246F511EEADD2A3230D6CDB14302502381
rsa_enc $e $n $M
#the result is 4FF3492B6ED0670EBCF132879ECFDE3FC073AFE5DFC9D7BF21B1D25D59E3BE9FBE8C0637BAC4E2F1677524D45D718ADA67D80FF961A1DB5FD65867E9D3C04E37
```

#### 6.2.4 decryption & sign

**COMMAND:**

```
rsa_dec d n C
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
| d        | private key                                 |
| n        | modulus                                     |
| C        | ciphertext                                  |

**EXAMPLE:**

```
set d A6A1E0F26DDCE4D2512010256D3431F77EE9EA99091A7AB30AFB1DEC1B52DEBF0DF420AAB94CC9E50253309B308011246F511EEADD2A3230D6CDB14302502381
set n AE98622E42C289499D28B88FAA3007C671111D448FF3B449D35D2C6999CE2C830BDAD6C38BA1AB356E227B3D626A5EB5716C1A1C319A00F7F2909FDBCA3CAECF
set C 4FF3492B6ED0670EBCF132879ECFDE3FC073AFE5DFC9D7BF21B1D25D59E3BE9FBE8C0637BAC4E2F1677524D45D718ADA67D80FF961A1DB5FD65867E9D3C04E37
rsa_dec $d $n $C
#the result is A6A1E0F26DDCE4D2512010256D3431F77EE9EA99091A7AB30AFB1DEC1B52DEBF0DF420AAB94CC9E50253309B308011246F511EEADD2A3230D6CDB14302502381
```

#### 6.2.5 crt

**EXAMPLE:**

```
rsa_crt p q dp dq qinv C
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|p         | the first prime number                      |
|q         | the second prime number                     |
|dp        | d mod (p-1)                                 |
|dq        | d mod (q-1)                                 |
|qinv      | q**-1 mod p                                 |

**EXAMPLE:**

```
set p E9CE7787806AD0699F9760DE166D34B41C149823759C82903B6188D8CD3B431F
set q BF2B12F6FB27E92DE31AE5CB3AA7957B4841335F59A057CE25C337E1F3D74E51
set dp B7DC5E50D762A80C37AD2246E399F35523B3EA44104C08BC8585D8C8ACF3CA7F
set dq 5CCFC2D35A3894430D01A0133D14E3C408DE6EDC9A1CF8C4431D3662630A6321
set qinv B059CF71886A2FB1F1C1C7D93C305B2A90A1FCFE0F75CD63919596432C5C3508
set C 4FF3492B6ED0670EBCF132879ECFDE3FC073AFE5DFC9D7BF21B1D25D59E3BE9FBE8C0637BAC4E2F1677524D45D718ADA67D80FF961A1DB5FD65867E9D3C04E37
rsa_crt $p $q $dp $dq $qinv $C

#the result is A6A1E0F26DDCE4D2512010256D3431F77EE9EA99091A7AB30AFB1DEC1B52DEBF0DF420AAB94CC9E50253309B308011246F511EEADD2A3230D6CDB14302502381
```

### 6.3 SM2

#### 6.3.1 hash z

**COMMAND:**

```
sm2_getz ID Pubkey
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|ID        | user ID                                     |
|Pubkey    | sm2 pubkey (x, y)                           |

**EXAMPLE:**

```
set id 1E3C
set Pkx 26EA8A3930208EFD9132F71C510AAB57438B3DBC27D304E798ECCAF2A0EA74EB
set Pky 7500D9CFF30E631015C773728E8C2509380A22E1E742B6ABA09DCF857C42CCEA
sm2_getz $id ${Pkx}${Pky}

#the result is a6ff86b98d0bf084d18a536e2d22816006dbc88eebd78902e3a5d19990fad9a9
```

#### 6.3.2 hash e

**COMMAND:**

```
sm2_gete Z M
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
| Z        | generated from sm2getz                      |
| M        | messages                                    |

**EXAMPLE:**

```
set za F13C4E7998FD743DA0FD887540E803F85A4286241391CA6659CB168B572DE0B1
set M 6D65737361676520646967657374
sm2_gete $za $M
#the result is fd780e1b1248655747c7842dba95b76be87d42037dd3af9b001ac8f4376c4090
```

#### 6.3.3 keygen

**COMMAND:**

```
sm2_keygen
```

|return code|
|-----------|
|{privatekey , publickey}|

**EXAMPLE:**

```
sm2_keygen

#the result is
#A95DBF5B0A09619CBCF588B7F975AA896E8F3C7BD1C81B0645CD438F0DA23BA2 #986850115D0D006D0FEFA2D68CA950831BFF91655228E072A6CF325922906DEA5DA27C4EE2DD4032C89EA865C00ADD62E668C2739D9A7FA524C7E2E436CAD2EF
```

#### 6.3.4 sign

**COMMAND:**

```
sm2_sig Random Prikey Ehash
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|Random    | random number of 16 bytes                   |
|Prikey    |  private key of 16 bytes                    |
|Ehash     |  the digest of hash e                       |

|return code |
|------------|
|(R||S)      |

**EXAMPLE:**

```
set rand A8D1A8EB9ED870073D5A75E3D85BA56ED7E8A034F618DD19A5A13E36AA392032
set  sk D84DC07A8426395E0CE43AEA82DB9ACCF2568D0F2D63772D9897D1334D1F20C3
set e 7C84316FC719431CA7921ACED955B407600C880F97D21826F438358051D0CB21
sm2_sig $rand $sk $e
#the result is 53572E8EE06A2DC311ED8A6087E6A0E71C8C42E360B10B55983397964F44ECFF3538D6F877B83AB3C9E298BBA7459C9629B533281A5A823EAC601DE8CFF5A0CB
```

#### 6.3.5 verify

**COMMAND:**

```
sm2_ver Pubkey RS Ehash
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|Pubkey    | public key of (Px, Py)                      |
|Ehash     | the digest of hash e                        |
|RS        | the signature of SM2                        |

|return code  |
|-------------|
|0- pass      |
|else fail    |

**EXAMPLE:**

```
set  pk CD459EA427E560E014F420F502055A20471AAE6B97CD5B66F01D87BAB250138B41DA65A7C7058F965EF911D6F5E45B536626DDE93E687C085EB506DC94BEDF79
set rs 53572E8EE06A2DC311ED8A6087E6A0E71C8C42E360B10B55983397964F44ECFF3538D6F877B83AB3C9E298BBA7459C9629B533281A5A823EAC601DE8CFF5A0CB
set e 7C84316FC719431CA7921ACED955B407600C880F97D21826F438358051D0CB21
sm2_ver $pk $rs $e
#the result is 0
```

#### 6.3.6 key exchange

**COMMAND:**

```
sm2_kex Role OutKeyByteLen ZSelf ZSide KeySelf RKeySelf PubKeySide RPubKeySide
```

|paras         | descrption                                  |
|--------------|---------------------------------------------|
|Role          |role 0-sender， 1-receiver
|OutKeyByteLen |the size of exchange key
|ZSelf         |the hash z of A (use sm2_getz)
|ZSide         |the hash z of B(sm2_getz)
|KeySelf       |the keypair {prikey pubkey} of A
|RKeySelf      |the temp keypaire {rprikey rpubkey} of A (use sm2_keygen)
|PubKeySide    |the public key of B
|RPubKeySide   |the temp public key of B


|return code |
|------------|
|{exchange_key, s1/sb, s2/sa}|

**EXAMPLE:**

```
#set a new curve.
set sm2_p 8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
set sm2_a 787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
set sm2_b 63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
set sm2_n 8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
set sm2_gx 421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
set sm2_gy 0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
set sm2_h 00000001
#==============================
#private key dA of A：
set dA 6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE
#public key PA of A：
set PA 3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE16553DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B
#private key dB of B：
set dB 5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53
#public key PB of B：
set PB 245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F4353C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C
#set digest ZA=H256(ENTLA||IDA||a||b||xG||yG||xA||yA)。
set ZA E4D1D0C3CA4C7F11BC8FF8CB3F4C02A78F108FA098E51A668487240F75E20F31
#set digest ZB=H256(ENTLB||IDB||a||b||xG||yG||xB||yB)。
set ZB 6B4B6D0E276691BD4A11BF72F4FB501AE309FDACB72FA6CC336E6656119ABD67

#temp private key rA of A：
set rdA 83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563
#temp public key RA of A：
set rPA 6CB5633816F4DD560B1DEC458310CBCC6856C09505324A6D23150C408F162BF00D6FCF62F1036C0A1B6DACCF57399223A65F7D7BF2D9637E5BBBEB857961BF1A
#temp private key rB of B：
set rdB 33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80
#temp public key RB of B：
set rPB 1799B2A2C778295300D9A2325C686129B8F2B5337B3DCF4514E8BBC19D900EE554C9288C82733EFDF7808AE7F27D0E732F7C73A7D9AC98B7D8740A91D0DB3CF4

#sender
sm2_kex 0 16 $ZA $ZB ${dA}${PA} ${rdA}${rPA} $PB $rPB

#receiver
sm2_kex 1 16 $ZB $ZA ${dB}${PB} ${rdB}${rPB} $PA $rPA

#the result is
#55b0ac62a6b927ba23703832c853ded4 #284c8f198f141b502e81250f1581c7e9eeb4ca6990f9e02df388b45471f5bc5c #23444daf8ed7534366cb901c84b3bdbb63504f4065c1116c91a4c00697e6cf7a
```

#### 6.3.7 encryption

**COMMAND:**

```
sm2_enc Random Pubkey M
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|Random    | random number of 16 bytes
|Pubkey    | public key of (Px, Py)
|M         | messages

|return code |
|------------|
|(c1||C3||C2)|

**EXAMPLE:**
```
set rand C9FFCE9C0FDFCD9962C5BF9CF5891F881531760D7D45E2D2E5E54A4006499243
set pk BC4EADB005F9AADF6BB8573DE5C430A12B023A2471402813CB4D066FC3D681648F98951D3EE032E6F4A4AB2B79510D5721767492E94F31B82C1603731E6CB92A
set m ce8f1ce36e5e62b16772
sm2_enc $rand $pk $m

#the result is E594A5745BBBD5539D68711C64CA55898A284C9081B65CA36E388062045A357C97AEFE68641FAB6E6A3E4E10855C7C3DE9B8F9417381E4FBB020E9303926BC77126d6f6f74993dd43233c284a0840040ef2e77b0383b9ef5f73b1803db7f4503C66D9F3544BCB59239D5
```

#### 6.3.8 decryption

**COMMAND:**

```
sm2_dec Prikey C
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|Prikey    |  private key of 16 bytes                    |
|C         |  ciphertext                                 |

**EXAMPLE:**

```
set sk 700BE499A4EFE27A8369F58BFFE0F5563CDFF772E11832254DDE10E324A81755
set c E594A5745BBBD5539D68711C64CA55898A284C9081B65CA36E388062045A357C97AEFE68641FAB6E6A3E4E10855C7C3DE9B8F9417381E4FBB020E9303926BC77126d6f6f74993dd43233c284a0840040ef2e77b0383b9ef5f73b1803db7f4503C66D9F3544BCB59239D5
sm2_dec $sk $c

#the result is CE8F1CE36E5E62B16772
```

## 7. random number

**COMMAND:**

```
rand NumByte smin smax
```

|paras     | descrption                                  |
|----------|---------------------------------------------|
|NumByte   | the size of random number
|smin      | the minimum value of one byte random number
|smax      | the maximum value of on byte random number


**EXAMPLE:**

```
rand 16 0 255
#the result is 7BEB05FC7F348FA2901088B1B2AD0A62
```

## 8. CRC

### 8.1 crc16

**COMMAND:**
```
crc16Ibm        data
for CRC-16, CRC-IBM, CRC-16/ARC, CRC-16/LHA

crc16AugCcitt   data
for CRC-16/AUG-CCITT, CRC-16/SPI-FUJITSU

crc16Buypass    data
for CRC-16/BUYPASS, CRC-16/VERIFONE

crc16CcittFalse data
for CRC-16/CCITT-FALSE

crc16Cdma2000   data
for CRC-16/CDMA2000

crc16Dds110     data
for CRC-16/DDS-100

crc16DectR      data
for CRC-16/DECT-R, R-CRC-16

crc16DectX      data
for CRC-16/DECT-X, X-CRC-16

crc16Dnp        data
for CRC-16/DNP

crc16En13757    data
for CRC-16/EN-13757

crc16Genibus    data
for CRC-16/GENIBUS, CRC-16/EPC, CRC-16/I-CODE, CRC-16/DARC

crc16Maxim      data
for CRC-16/MAXIM

crc16Mcrf4xx    data
for CRC-16/MCRF4XX

crc16Riello     data
for CRC-16/RIELLO

crc16T10Dif     data
for CRC-16/T10-DIF

crc16Teledisk   data
for CRC-16/TELEDISK

crc16Tms37157   data
for CRC-16/TMS37157

crc16Usb        data
for CRC-16/USB

crcA            data
for CRC-A

crcB            data
for CRC-B

crc16Ccitt      data
for CRC-16/CCITT, CRC-16/CCITT-TRUE, CRC-16/KERMIT, CRC-CCITT

crc16Modbus     data
for MODBUS

crc16X25        data
for X-25, CRC-16/IBM-SDLC, CRC-16/ISO-HDLC, CRC-B

crc16Xmodem     data
for XMODEM, ZMODEM, CRC-16/ACORN
```

##9. util

### 9.1 dec2hex

**COMMAND:**
```
dec2hex dec

dec2hex2 num args_list
```

**EXAMPLE:**

```
dec2hex 16
#the result is 10

dec2hex 3 16 17 18
#the result is 101112
```

### 9.2 endian

**COMMAND:**

```
endian str
```

**EXAMPLE:**

```
endian 00112233445566778899
#the result is 99887766554433221100
```

### 9.3 hex2bin

**COMMAND:**

```
Hex2bin str

hex2binfile srcfile dstfile

hexstr2binfile str dstfile
```

**EXAMPLE:**

```
hex2bin 303132333435
#the result is 012345
```

### 9.4 bin2hex

**COMMAND:**

```
bin2hex str

bin2hexfile srcfile dstfile
```

**EXAMPLE:**

```
bin2hex 012345
#the result is 303132333435
```

### 9.5 strsp

**COMMAND:**

```
strsp str delimiter
```

**EXAMPLE:**

```
strsp 01020304 ,
#the result is 01,02,03,04
```

### 9.7 strcat

**COMMAND:**

```
strcat str args
```

**EXAMPLE:**

```
strcat 01 02 03 04
#the result is 01020304
```

## 10 AEAD

### 10.1 aes_ccm (need to update)

**COMMAND:**

```
aesccm_enc L M Nonce Msg AAD key
```


|paras     | descrption                                  |
|----------|---------------------------------------------|
| L        |
| M        |
| Nonce    |
| Msg      |
| AAD      |
| key      |


**EXAMPLE:**

```
set key c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
set nonce 00000003020100a0a1a2a3a4a5
set Msg 08090a0b0c0d0e0f101112131415161718191a1b1c1d1e
set AAD 0001020304050607
set M 8
set L 2
aesccm_enc $L $M $nonce $Msg $AAD $key
#the result is {588c979a61c663d2f066d0c2c0f989806d5f6b61dac384 17e8d12cfdf926e0}
```

## 11 ECC

### ecdsa_sign

**COMMAND:**

```
ecdsa_sign hmode curve privkey msg

```


|paras     | descrption                                  |
|----------|---------------------------------------------|
|hmode     | support sha1/sha224/sha256/sha384/sha512
|curve     | support secp192r1/secp192k1/secp224r1/secp224r1/secp256r1/secp256k1/secp384r1/secp521r1
|privkey   | private key
|msg       | msg to be signed

**EXAMPLE:**

```
set msg 0102030405
set curve secp224k1
set hmode sha224


set keys [ecc_keygen $curve]
set k [lindex $keys 0]
set Q [lindex $keys 1]

set sig [ecdsa_sign $hmode $curve $k $msg]
puts $sig
set r [lindex $sig 0]
set s [lindex $sig 1]

puts [ecdsa_verify $hmode $curve $Q ${r}$s $msg]
```

### ecdsa_verify

**COMMAND:**

```
ecdsa_verify hmode curve pubkey sig msg

```


|paras     | descrption                                  |
|----------|---------------------------------------------|
|hmode     | support sha1/sha224/sha256/sha384/sha512
|curve     | support secp192r1/secp192k1/secp224r1/secp224r1/secp256r1/secp256k1/secp384r1/secp521r1
|pubkey    | public key
|sig       | signature
|msg       | msg to be signed

**EXAMPLE:**

```
set msg 0102030405
set curve secp224k1
set hmode sha224


set keys [ecc_keygen $curve]
set k [lindex $keys 0]
set Q [lindex $keys 1]

set sig [ecdsa_sign $hmode $curve $k $msg]
puts $sig
set r [lindex $sig 0]
set s [lindex $sig 1]

puts [ecdsa_verify $hmode $curve $Q ${r}$s $msg]
```
## 12 Stream

### 12.1 chacha20


**COMMAND:**

```
chacha20_block key counter nonce
```

**EXAMPLE:**

```
set key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
set nonce 000000090000004a00000000
set counter 00000001
chacha20_block $key $counter $nonce
#the result : 10F1E7E4D13B5915500FDD1FA32071C4C7D1F4C733C068030422AA9AC3D46C4ED2826446079FAA0914C2D705D98B02A2B5129CD1DE164EB9CBD083E8A2503C4E
```

### 12.2 poly1305_mac

**COMMAND:**

```
poly1305_mac msg key
```

**EXAMPLE:**

```
set msg 43727970746f6772617068696320466f72756d2052657365617263682047726f7570
set key 85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b
poly1305_mac $msg $key
#the result : a8061dc1305136c6c22b8baf0c0127a9
```

### 12.3 rc4

**COMMAND:**

```
rc4_enc key msg
rc4_dec key msg
```

**EXAMPLE:**

```
set key 0102030405
set msg 0203040506
rc4_enc $key $msg
#the result: b03a6700f6
```
