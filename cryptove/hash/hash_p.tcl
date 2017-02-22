#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#hash for Tcl
#
#md5, sha(1,224,256,384,512), sm3
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#1. md5 messages
#2. sha 1 messages
#3. sha 224 messages
#4. sha 256 messages
#5. sha 384 messages
#6. sha 512 messages
#7. sm3 messages
#===============================================================================

package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]

#hash funtion in libcrypto library
