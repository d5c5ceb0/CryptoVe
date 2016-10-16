#===============================================================================
#SM4算法Tcl实现
#
#实现了SM4加解密功能，包括SM4 ECB模式加解密
#
#Wei zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#函数介绍
#1. sm4ecb  SM4 ECB模式加解密                   sm4ecb mode key data
#===============================================================================

package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]

#sm4 ecb in libcrypto library
