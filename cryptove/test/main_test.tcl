#!/usr/bin/tclsh
#===============================================================================
# main test case for TCL
#
# all test
#
# Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
# functions:
#===============================================================================
#

source [file join [file dirname [info script]] ./test_cipher.tcl]
source [file join [file dirname [info script]] ./test_hash.tcl]
source [file join [file dirname [info script]] ./test_mac.tcl]
source [file join [file dirname [info script]] ./test_crc.tcl]
source [file join [file dirname [info script]] ./test_pk.tcl]
source [file join [file dirname [info script]] ./test_stream.tcl]


proc test_case { algo } {
	switch $algo {
		AES {
			test_aes_ecb
			test_aes_cbc
			test_aes_cfb
			test_aes_ofb
			test_aes_ctr
			test_aes_xts
		}
		DES {
			test_des_ecb
			test_des_cbc
			test_des3_ecb
			test_des3_cbc
		}
		SM4 {
			test_sm4_ecb
			test_sm4_cbc
		}
		HASH {
			test_hash_md5
			test_hash_sha1
			test_hash_sha224
			test_hash_sha256
			test_hash_sha384
			test_hash_sha512
			test_hash_sm3
		}
		HMAC {
			test_hmac_md5
			test_hmac_sha1
			test_hmac_sha224
			test_hmac_sha256
			test_hmac_sha384
			test_hmac_sha512
		}
		CMAC {
			test_cmac
			test_cbcmac
			test_xcbcmac
		}
		CRC {
			test_crc16
		}
		RSA {
			test_rsa
		}
		SM2 {
			test_sm2
		}
		ECC {
			test_ecc
		}
		PKCS1 {
			test_pkcs1
		}
		RC4 {
			test_rc4
		}
		CHACHA20_POLY1305 {
			test_chacha20_poly1305
		}
	}
}

proc main_test {} {
	while {1} {
		puts "==================================================="
		puts "# CryptoVe algorithm test case: #"
		puts  {1 - AES algorithm test cases.}
		puts  {2 - DES algorithm test cases.}
		puts  {3 - SM4 algorithm test cases.}
		puts  {4 - HASH algorithm test cases.}
		puts  {5 - HMAC algorithm test cases.}
		puts  {6 - CMAC algorithm test cases.}
		puts  {7 - CRC algorithm test cases.}
		puts  {8 - RSA algorithm test cases.}
		puts  {9 - SM2 algorithm test cases.}
		puts  {a - ECC algorithm test cases.}
		puts  {b - PKCS1 algorithm test cases.}
		puts  {c - RC4 algorithm test cases.}
		puts  {d - CHACHA20_POLY1305 algorithm test cases.}
		puts  {e - ALL algorithms test cases.}
		puts  {0 - exit.}
		puts "==================================================="
		puts "select the test case:"
		gets stdin sel
		switch $sel {
			0 {return}
			1 {
				test_case AES
			}
			2 {
				test_case DES
			}
			3 {
				test_case SM4
			}
			4 {
				test_case HASH
			}
			5 {
				test_case HMAC
			}
			6 {
				test_case CMAC
			}
			7 {
				test_case CRC
			}
			8 {
				test_case RSA
			}
			9 {
				test_case SM2
			}
			a {
				test_case ECC
			}
			b {
				test_case PKCS1
			}
			c {
				test_case RC4
			}
			d {
				test_case CHACHA20_POLY1305
			}
			e {
				test_case AES
				test_case DES
				test_case SM4
				test_case HASH
				test_case HMAC
				test_case CMAC
				test_case CRC
				test_case RSA
				test_case SM2
				test_case ECC
				test_case PKCS1
				test_case RC4
				test_case CHACHA20_POLY1305
			}
			default {continue}
		}
	}
}

main_test
