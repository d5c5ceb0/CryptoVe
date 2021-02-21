#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#===============================================================================

load [file join [file dirname [info script]] lib/libcrypto[info sharedlibextension]]
source [file join [file dirname [info script]] cipher/cipher_api.tcl]
source [file join [file dirname [info script]] hash/hash_api.tcl]
source [file join [file dirname [info script]] mac/hmac_api.tcl]
source [file join [file dirname [info script]] mac/cbc_mac.tcl]
source [file join [file dirname [info script]] crc/crc16.tcl]
source [file join [file dirname [info script]] rng/rng.tcl]
source [file join [file dirname [info script]] pk/rsa.tcl]
source [file join [file dirname [info script]] pk/sm2.tcl]
source [file join [file dirname [info script]] pk/ecc.tcl]
source [file join [file dirname [info script]] pk/pkcs1.tcl]
source [file join [file dirname [info script]] pk/bignum.tcl]
source [file join [file dirname [info script]] stream/rc4.tcl]
source [file join [file dirname [info script]] stream/chacha20_poly1305.tcl]
source [file join [file dirname [info script]] common/common.tcl]
source [file join [file dirname [info script]] common/util.tcl]
