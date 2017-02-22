#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#SM4
#
#Wei zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#
#1. sm4ecb  SM4 ECB                  sm4ecb mode key data
#===============================================================================

package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]

#sm4 ecb in libcrypto library
