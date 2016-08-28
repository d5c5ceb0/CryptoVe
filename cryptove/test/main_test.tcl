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


##cipher testing
test_aes_ecb
test_aes_cbc
test_aes_cfb
test_aes_ofb
test_aes_ctr
test_aes_xts
test_des_ecb
test_des_cbc
test_des3_ecb
test_des3_cbc
test_sm4_ecb
test_sm4_cbc

##hash test
test_hash_md5
test_hash_sha1
test_hash_sha224
test_hash_sha256
test_hash_sha384
test_hash_sha512
test_hash_sm3
#
##mac test
test_hmac_md5
test_hmac_sha1
test_hmac_sha224
test_hmac_sha256
test_hmac_sha384
test_hmac_sha512
test_cmac
test_cbcmac
test_xcbcmac

##crc test
test_crc16

## pk testing 
test_rsa
test_sm2

