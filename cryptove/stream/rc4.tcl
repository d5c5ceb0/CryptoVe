#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#rc4 api for TCL
#
#rc4 api
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#º¯Êý½éÉÜ
#1. rc4_enc
#2. rc4_dec
#=============================================================================================

package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]


proc rc4_enc {key msg} {
	set msglen [expr [string length $msg]/2]
	set keylen [expr [string length $key]/2]
	for {set i 0} {$i < 256} {incr i 1} {
		set S($i) [format %02x $i]
		set T($i) [string range $key [expr $i%$keylen*2] [expr $i%$keylen*2+1]]
	}

	set j 0
	for {set i 0} {$i < 256} {incr i 1} {
		set j [expr ($j + 0x$S($i) + 0x$T($i))%256]
		set temp $S($j)
		set S($j) $S($i) 
		set S($i) $temp
	}

	set i 0
	set j 0
	set t 0
	set out ""
	for {set r 0} {$r < $msglen} {incr r 1} {
		set i [expr ($i + 1)%256]
		set j [expr ($j + 0x$S($i))%256]
		set temp $S($j)
		set S($j) $S($i) 
		set S($i) $temp
		set t [expr (0x$S($i) + 0x$S($j))%256]
		set iK($r) $S($t)
		append out [xor $iK($r) [string range $msg [expr $r*2] [expr ($r+1)*2-1]]]
	}
	return $out
}

proc rc4_dec {key msg} {
	return [rc4_enc $key $msg]
}



