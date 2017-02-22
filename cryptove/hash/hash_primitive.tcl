#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#hash for TCL
#
#block cipher primitive
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#content
#	cipher_list
#	register_cipher name primitive key_len_list block_len
#	unregister_cipher name
#	aes_p dir key block
#	des_p dir key block
#	des3_p dir key block
#	sm4_p dir key block
#===============================================================================

package provide crypto 1.0.0

source [file join [file dirname [info script]] hash_p.tcl]

#
## hash list
## example:
## name {primitive block_len digest_len}
## md5  {md5_p     64        16}
#
set hash_list {
	md5		{md5_p       64  	16}
	sha1	{sha1_p      64  	20}
	sha224	{sha224_p    64  	28}
	sha256	{sha256_p    64  	32}
	sha384	{sha384_p    128 	48}
	sha512	{sha512_p    128 	64}
	sm3		{sm3_p       64  	32}
}

##
#hash primitive
#[hash_name messages]
##
proc md5_p {messages} {
	md5 $messages	
}

proc sha1_p {messages} {
	sha 1 $messages
}

proc sha224_p {messages} {
	sha 224 $messages
}

proc sha256_p {messages} {
	sha 256 $messages
}

proc sha384_p {messages} {
	sha 384 $messages
}

proc sha512_p {messages} {
	sha 512 $messages
}

proc sm3_p {messages} {
	sm3 $messages
}

