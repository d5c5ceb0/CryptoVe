#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#pkcs1 api for TCL
#
#pkcs1 api
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#commands
#eme_oaep_encode 
#eme_oaep_decode 
#eme_pkcs1_v1_5_encode 
#eme_pkcs1_v1_5_decode 
#emsa_pkcs1_v1_5_encode 
#emsa_pss_encode 
#emsa_pss_decode
#rsa_sign_pss
#rsa_verify_pss
#=============================================================================================

package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]

##
# EME_OAEP_encode
#
# input
#        label     optional label to be associated with the message
#        msg       message to be encrypted
#        hash_func the hash function
#        klen      the length in octets of the RSA modulus n
# output 
#        em     encoded message em
# return 
#        00     success
##
proc eme_oaep_encode {em label msg hashtype klen} {
	upvar $em emsg

	switch $hashtype {
		sha1   {set cmd sha1_process; set hlen 20}
		sha224 {set cmd sha224_process; set hlen 28}
		sha256 {set cmd sha256_process; set hlen 32}
		sha384 {set cmd sha384_process; set hlen 48}
		sha512 {set cmd sha512_process; set hlen 64}
		default {set cmd sha1_process; set hlen 20}
	}

	set lhash [$cmd $label]
	set mlen  [expr [string length $msg]/2]
	set ps [string repeat 00 [expr $klen - 2*$hlen - $mlen - 2]]
	set db ${lhash}${ps}01$msg
	
	set seed [rand $hlen 0 256]

	set db_mask [mgf1 $hashtype $seed [expr $klen - $hlen - 1]]
	set masked_db [xor $db $db_mask]
	set seed_mask [mgf1 $hashtype $masked_db $hlen]
	set masked_seed [xor $seed $seed_mask]
	
	set emsg 00${masked_seed}${masked_db}

	return 00
}


##
# eme_oaep_decode
#
# label optional label to be associated with the message
# em encode messages
# hash_name the hash function 
# seed seed of mask
# klen the length in octets of the RSA modulus n
# ##

##
# EME_OAEP_decode
#
# input
#        label     optional label to be associated with the message
#        em        encoded message em
#        hash_func the hash function
#        klen      the length in octets of the RSA modulus n
# output 
#        msg       message to be encrypted
# return 
#        00     success
#        01     y == 00
#        02     digest on equal
#        03     on 01
#        04     ps no cosist of 00
##

proc eme_oaep_decode {msg label em hashtype klen} {
	upvar $msg m

	switch $hashtype {
		sha1   {set cmd sha1_process; set hlen 20}
		sha224 {set cmd sha224_process; set hlen 28}
		sha256 {set cmd sha256_process; set hlen 32}
		sha384 {set cmd sha384_process; set hlen 48}
		sha512 {set cmd sha512_process; set hlen 64}
		default {set cmd sha1_process; set hlen 20}
	}
	
	set lhash [$cmd $label]
	set emlen [expr [string length $em]/2]

	# em [00||masked_seed||masked_db]
	set y [string range $em 0 1]
	set sub_em [string range $em 2 end]
	set masked_seed [string range $sub_em 0 [expr $hlen*2-1]]
	set sub_em [string range $sub_em [expr $hlen*2] end]
	set masked_db $sub_em

	if {$y != {00}} {
		return 01
	}

	set seed_mask [mgf1 $hashtype $masked_db $hlen]
	set seed [xor $seed_mask $masked_seed]
	set db_mask   [mgf1 $hashtype $seed [expr $klen - $hlen - 1]]
	set db [xor $db_mask $masked_db]
	
	# db  [lhash2||ps||01||m]
	set lhash2 [string range $db 0 [expr $hlen*2-1]]
	if {$lhash != $lhash2} {
		return 02
	}
	set sub_db [string range $db [expr $hlen*2] end]

	set idx [string first 01 $sub_db]
	if {$idx == -1 } {
		return 03
	}
	set ps [string range $sub_db 0 [expr $idx-1]]
	set pslen [expr [string length $ps]/2]
	set ps2 [string repeat 00 $pslen]
	if {$ps2 != $ps} {
		return 04
	}

	set sub_db [string range $sub_db $idx end]
	set m [string range $sub_db 2 end]

	return $m
}

##
# EME_PKCS1_v1.5_encode
#
# input
#        klen   the length in octets of the modulus n
#        msg     message to be encrypted
# output 
#        em     encoded message em
# return 
#        00     success
##
proc eme_pkcs1_v1_5_encode {em msg klen} {
	upvar $em emsg
	
	set mlen [expr [string length $msg]/2]
	set pslen [expr $klen - $mlen - 3]
	set ps ""
	for {set i 0} {$i<$pslen} {incr i 1} {
		append ps [rand 1 1 256]
	}
	
	# EM = [00||02||ps||00||msg]
	set emsg 0002${ps}00${msg}
	
	return 00
}

##
# EME_PKCS1_v1.5_decode
#
# input
#        klen   the length in octets of the modulus n
#        em     encoded message em
# output 
#        msg    message
# return 
#        00     success
#        01     first and secord bytes are not 0002
#        02     the length of ps is less than 8
#        03     there is not zero separate ps from m
##
proc eme_pkcs1_v1_5_decode {msg em klen} {
	upvar $msg m
	
	set emlen [expr [string length $em]/2]
	set prefix [string range $em 0 3]
	if {$prefix != 0002} {
		return 01
	}

	set sub_em [string range $em 4 end]
	set ps ""
	while {[string length $sub_em]} {
		if {[string range $sub_em 0 1] == 00} {
			break
		}
		append ps  [string range $sub_em 0 1]
		set sub_em [string range $sub_em 2 end]
	}
	
	if {[string length $ps]/2 < 8} {
		return 02
	}
	if {![string length $sub_em]} {
		return 03
	}

	set m [string range $sub_em 2 end]
	
	return 00
}

##
# mgf1 is a mask generation function based on a hash function
##
proc  mgf1 {hashtype mgf_seed mask_len} {
	switch $hashtype {
		sha1   {set cmd sha1_process; set hlen 20}
		sha224 {set cmd sha224_process; set hlen 28}
		sha256 {set cmd sha256_process; set hlen 32}
		sha384 {set cmd sha384_process; set hlen 48}
		sha512 {set cmd sha512_process; set hlen 64}
		default {set cmd sha1_process; set hlen 20}
	}

	# TODO check maskLen
	set temp $mask_len
	set tlen [expr ($mask_len+$hlen-1)/$hlen]
	set t ""
	for {set counter 0} {$mask_len > 0} {incr counter 1} {
		set c [format %08x $counter]
		append t [$cmd ${mgf_seed}$c]
		set mask_len [expr $mask_len - $hlen]
	}

	return [string range $t 0 [expr 2*$temp-1]]
}


proc emsa_pss_encode {hashtype msg salt embits} {

	switch $hashtype {
		sha1   {set cmd sha1_process; set hlen 20}
		sha224 {set cmd sha224_process; set hlen 28}
		sha256 {set cmd sha256_process; set hlen 32}
		sha384 {set cmd sha384_process; set hlen 48}
		sha512 {set cmd sha512_process; set hlen 64}
		default {set cmd sha1_process; set hlen 20}
	}

	puts "cmd=$cmd"
	puts "hlen=$hlen"
	set emlen [expr ($embits+7)/8]
	set leftbits [expr $emlen*8 - $embits]
	
	set mhash [$cmd $msg]
	set slen [expr [string length $salt]/2]
	if {$emlen <$hlen+$slen+2} {
		return 01
	}
	
	#set salt [rand $slen 0 256]
	set md [string repeat 00 8]${mhash}${salt}
	set h [$cmd $md]
	
	set ps [string repeat 00 [expr $emlen-$hlen-$slen-2]]
	set db ${ps}01${salt}
	set db_mask [mgf1 $hashtype $h [expr $emlen-$hlen-1]] 
	set masked_db [xor $db $db_mask]
	set leftbyte [and [string range $masked_db 0 1] [sft R ff $leftbits]]
	set masked_db ${leftbyte}[string range $masked_db 2 end]
	set em ${masked_db}${h}bc
	return $em
}


proc emsa_pss_decode {hashtype msg em embits} {
	set emlen [expr ($embits+7)/8]
	set leftbits [expr $emlen*8 - $embits]

	switch $hashtype {
		sha1   {set cmd sha1_process; set hlen 20}
		sha224 {set cmd sha224_process; set hlen 28}
		sha256 {set cmd sha256_process; set hlen 32}
		sha384 {set cmd sha384_process; set hlen 48}
		sha512 {set cmd sha512_process; set hlen 64}
		default {set cmd sha1_process; set hlen 20}
	}

	puts "cmd=$cmd"
	puts "hlen=$hlen"

	set suffix [string range $em end-1 end]
	if {[expr 0x$suffix] != 0xbc} {
		return 02
	}
	
	set sub_em [string range $em 0 end-2]
	set masked_db [string range $sub_em 0 [expr ($emlen-$hlen-1)*2-1]]
	set h [string range $sub_em [expr ($emlen-$hlen-1)*2] end]

	set leftbyte [and [string range $masked_db 0 1] [not [sft R ff $leftbits]]]
	if {[expr 0x$leftbyte] != 0x00} {
		return 03
	}
	set db_mask [mgf1 $hashtype $h [expr $emlen-$hlen-1]] 
	set db [xor $masked_db $db_mask]
	puts $db
	set leftbyte [and [string range $db 0 1] [sft R ff $leftbits]]
	set db2 $leftbyte[string range $db 2 end]
	set sub_db $db2
	for {set i 0} {[string range $sub_db 0 1] == 00} {incr i 1} {
		set sub_db [string range $sub_db 2 end]
	}
	
	if {[string range $sub_db 0 1] != 01} {
		return 04
	}
	
	set salt [string range $sub_db 2 end]
	puts "salt=$salt"
	
	set msg_hash [$cmd $msg]
	set m [string repeat 00 8]${msg_hash}${salt}
	set mhash [$cmd $m]
	puts "mhash=$mhash"
	puts "h=$h"
	if {[cmp $h $mhash]} {
		return 05
	}

	return 00
}


proc emsa_pkcs1_v1_5_encode {hashtype msg emlen} {
	switch $hashtype {
		sha1   {
			set cmd   sha1_process
			set hlen  20
			set Tder 3021300906052b0e03021a05000414
		}
		sha224 {
			set cmd sha224_process
			set hlen 28
			set Tder 302d300d06096086480165030402040500041c
		}
		sha256 {
			set cmd sha256_process
			set hlen 32
			set Tder 3031300d060960864801650304020105000420
		}
		sha384 {
			set cmd sha384_process
			set hlen 48
			set Tder 3041300d060960864801650304020205000430
		}
		sha512 {
			set cmd sha512_process
			set hlen 64
			set Tder 3051300d060960864801650304020305000440
		}
		default {
			set cmd sha1_process
			set hlen 20
			set Tder 3021300906052b0e03021a05000414
		}
	}

	set mhash [$cmd $msg]
	set T ${Tder}$mhash
	puts $T

	set Tlen [expr [string length $T]/2]
	if {$emlen < ($Tlen+11)} {
		return -code error "intended encoded message length too short"
	}
	
	set PS [string repeat FF [expr $emlen - $Tlen - 3]]
	puts $PS

	set EM 0001${PS}00${T}
	return $EM
}

proc bitlen {str} {

	set count 0
	set str2 $str
	while {[and FF [string range $str2 0 1]] == 00} {
		set count [expr $count + 8]
		set str2 [string range $str2 2 end]
	}
	
	set sub_str [string range $str2 0 1]
	for {set i 7} {$i>=0} {incr i -1 } {
		if {[and $sub_str [sft L 01 $i]] != 00} {
			break
		}
		incr count
	}
	
	return $count
	
}

proc rsa_pkcs1_v15_sig {d n hmode din bitlen} {
    set em [emsa_pkcs1_v1_5_encode $hmode $din [expr $bitlen / 8]]
    set sig [rsa_dec $d $n $em]
    return $sig
}

proc rsa_pkcs1_v15_ver {e n hmode din sig bitlen} {
    set em [rsa_enc $e $n $sig]
    set ret [emsa_pkcs1_v1_5_encode $hmode $em [expr $bitlen / 8]]
    return $ret
}

proc rsa_pkcs1_pss_sign {d n hmode din salt bitlen} {
    set em [emsa_pss_encode $hmode $din $salt [expr $bitlen - 1]]
    set rs [rsa_dec $d $n $em]
    return $rs
}

proc rsa_pkcs1_pss_ver {e n hmode din sig bitlen} {
    set em [rsa_enc $e $n $sig]
    set ret [emsa_pss_decode $hmode $din $em [expr $bitlen - 1]]
    return $ret
}

proc rsa_pkcs1_v15_enc { e n din bitlen} {
    eme_pkcs1_v1_5_encode em $din [expr $bitlen / 8]
    set em [rsa_enc $e $n $em]
    return $em
}

proc rsa_pkcs1_v15_dec {d n din bitlen} {
    set mm ""
    set em [rsa_dec $d $n $din]
    eme_pkcs1_v1_5_decode mm 00$em [expr $bitlen / 8]
    return $mm
}

proc rsa_pkcs1_oaep_enc {e n hmode din bitlen} {
    set em ""
    eme_oaep_encode em "" $din $hmode [expr $bitlen / 8]
    set ret [rsa_enc $e $n $em]
    return $ret
}
proc rsa_pkcs1_oaep_dec {d n hmode din bitlen} {
    set mm ""
    set em [rsa_dec $d $n $din]
    set ret [eme_oaep_decode mm "" 00$em $hmode [expr $bitlen / 8]]
    return $mm
}
