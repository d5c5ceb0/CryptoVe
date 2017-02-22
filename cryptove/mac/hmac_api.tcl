#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#hmac api for TCL
#
#hmac api
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#===============================================================================

package provide crypto 1.0.0

source [file join [file dirname [info script]] ../common/common.tcl]
source [file join [file dirname [info script]] ../hash/hash_primitive.tcl]

##
# hmac_init
# ctx - a context of alg
# alg - element of hash_list
##


proc hmac_init {alg ctx key} {
	global hash_list
	global block_type
	
	upvar $ctx ref_ctx

	if {[lsearch [dict keys $hash_list] $alg] < 0} {
		return -code error [ret_code hmac_init ERR_ARGS "hmac wrong!"]
	}
	set hash_alg [lindex [dict get $hash_list $alg] 0]
	set hash_blocklen [lindex [dict get $hash_list $alg] 1]
	set hash_digestlen [lindex [dict get $hash_list $alg] 2]

	set klen [expr [string length $key]/2]
	if {$klen > $hash_blocklen } {
		set hkey [$hash_alg $key]
		append hkey [string repeat 00 [expr $hash_blocklen - $hash_digestlen]]
	} else {
		set hkey $key
		append hkey [string repeat 00 [expr $hash_blocklen - $klen]]
	}

	set ipad [string repeat 36 $hash_blocklen]
	

	dict set ref_ctx  _alg 			$hash_alg
	dict set ref_ctx  _block_len 	$hash_blocklen
	dict set ref_ctx  _digest_len 	$hash_digestlen
	dict set ref_ctx  _key			$hkey
	dict set ref_ctx  _block_type 	[dict get $block_type first_block]
	dict set ref_ctx  _digest 		""
	dict set ref_ctx  _message      [xor $hkey $ipad]
}

##
# hmac_update
# ctx - a context of hmac
# messages - messages
##
proc hmac_update {ctx messages} {
	global block_type
	upvar $ctx ref_ctx
	
	set temp [dict get $ref_ctx  _message]
	append temp $messages
	dict set ref_ctx  _message	$temp
	dict set ref_ctx  _block_type [dict get $block_type middle_block]
	return
}	

##
# hmac_done
# ctx - a context of hmac
##
proc hmac_done {ctx} {
	global block_type
	upvar $ctx ref_ctx

	#check ctx
	if {![dict exists $ref_ctx _alg]} {
		return -code error [ret_code hash_update ERR_ARGS "ctx._alg wrong"]
	}
	set alg [dict get $ref_ctx _alg]
	set fst_digest [$alg [dict get $ref_ctx _message]]

	set hkey [dict get $ref_ctx _key]
	set blocklen [dict get $ref_ctx _block_len]
	set opad [string repeat 5c $blocklen]
	set temp [xor $hkey $opad]${fst_digest}

	dict set ref_ctx _digest [$alg $temp]
	dict set ref_ctx  _block_type [dict get $block_type last_block]
	return [dict get $ref_ctx _digest]
}

##
# hmac_process
##
proc hmac_process {alg key messages} {
	hmac_init $alg ctx $key
	hmac_update ctx $messages
	return [hmac_done ctx]
}


proc create_hmac {} {
	global hash_list
	
	foreach hash [dict key $hash_list] {
			proc ${hash}_hmac_init {ctx key} {
				upvar $ctx ref_ctx

				set func_name [lindex [info level 0] 0]
				set hash_name [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
				hmac_init $hash_name ref_ctx $key
			}
			proc ${hash}_hmac_update {ctx messages} {
				upvar $ctx ref_ctx

				hmac_update ref_ctx $messages
			}
			proc ${hash}_hmac_done {ctx} {
				upvar $ctx ref_ctx

				hmac_done ref_ctx
			}
			proc ${hash}_hmac_process {key messages} {

				set func_name [lindex [info level 0] 0]
				set hash_name [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
				hmac_process $hash_name $key $messages
			}
	}
}


#new hmac init
set rt_code [create_hmac]

puts "load hmaces successfully"
