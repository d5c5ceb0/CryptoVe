#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#cipher primitive for TCL
#
#block cipher primitive
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#	cipher_list
#	register_cipher name primitive key_len_list block_len
#	unregister_cipher name
#	aes_p dir key block
#	des_p dir key block
#	des3_p dir key block
#	sm4_p dir key block
#===============================================================================

package provide crypto 1.0.0


source [file join [file dirname [info script]] aes_p.tcl]
source [file join [file dirname [info script]] des_p.tcl]
source [file join [file dirname [info script]] sm4_p.tcl]
source [file join [file dirname [info script]] ../common/common.tcl]


#
## cipher list
## example:
## name {primitive key_len_list block_len}
## aes  {aes_p     {16 24 32}   16}
#
set cipher_list {
	aes  {aes_p  {16 24 32}    16}
	des  {des_p  {8       }    8 }
	des3 {des3_p {16 24   }    8 }
	sm4  {sm4_p  {16      }    16}
}

#
## func_name dir key block
# dir : ENC for encrypt, DEC for decrypt
# key : user key
# block: one block of message

proc aes_p {dir key block} {
	global cipher_direction
	
	set dir [dict get $cipher_direction $dir]
	aesecb $dir $key $block	
}

proc des_p {dir key block} {
	global cipher_direction
	
	set dir [dict get $cipher_direction $dir]
	desecb $dir $key $block
}

proc des3_p {dir key block} {
	global cipher_direction
	
	set dir [dict get $cipher_direction $dir]
	tdesecb $dir $key $block
}

proc sm4_p {dir key block} {
	global cipher_direction
	
	set dir [dict get $cipher_direction $dir]
	sm4ecb $dir $key $block
}
