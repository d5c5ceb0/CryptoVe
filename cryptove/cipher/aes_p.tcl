#===============================================================================
#AES for Tcl
#
#aes ecb encrypt & decrypt, contain of three key size(128B, 192B, 256B).
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#1. aesecb  aesecb mode key data
#===============================================================================

package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto.so]

#aes ecb funtion in libcrypto.so
