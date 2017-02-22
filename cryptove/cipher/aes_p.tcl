#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
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

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]

#aes ecb funtion in libcrypto library
