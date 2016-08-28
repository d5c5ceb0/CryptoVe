#===============================================================================
#hash api for TCL
#
#hash api
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#===============================================================================

package provide crypto 1.0.0

source [file join [file dirname [info script]] ../common/common.tcl]
source [file join [file dirname [info script]] hash_primitive.tcl]

##
# hash_init
# ctx - a context of alg
# alg - element of hash_list
##
proc hash_init {alg ctx} {
	global hash_list
	global block_type
	
	upvar $ctx ref_ctx

	if {[lsearch [dict keys $hash_list] $alg] < 0} {
		return -code error [ret_code hash_init ERR_ARGS "hash wrong!"]
	}

	dict set ref_ctx  _alg 			[lindex [dict get $hash_list $alg] 0]
	dict set ref_ctx  _block_len 	[lindex [dict get $hash_list $alg] 1]
	dict set ref_ctx  _digest_len 	[lindex [dict get $hash_list $alg] 2]
	dict set ref_ctx  _block_type 	[dict get $block_type first_block]
	dict set ref_ctx  _digest 		""
	dict set ref_ctx  _message      ""
}

##
# hash_update
# ctx - a context of hash
# messages - messages
##
proc hash_update {ctx messages} {
	global block_type

	upvar $ctx ref_ctx

	set temp [dict get $ref_ctx  _message]
	append temp $messages
	dict set ref_ctx  _message	$temp
	dict set ref_ctx  _block_type [dict get $block_type middle_block]
	return
}	

##
# hash_done
# ctx - a context of hash
##
proc hash_done {ctx} {
	global block_type
	upvar $ctx ref_ctx

	#check ctx
	if {![dict exists $ref_ctx _alg]} {
		return -code error [ret_code hash_update ERR_ARGS "ctx._alg wrong"]
	}
	set alg [dict get $ref_ctx _alg]
	dict set ref_ctx _digest [$alg [dict get $ref_ctx _message]]
	dict set ref_ctx  _block_type [dict get $block_type last_block]

	return [dict get $ref_ctx _digest]
}

##
# hash_process
##
proc hash_process {alg messages} {
	hash_init $alg ctx
	hash_update ctx $messages
	return [hash_done ctx]
}


proc create_hash {} {
	global hash_list
	
	foreach hash [dict key $hash_list] {
			proc ${hash}_init {ctx} {
				upvar $ctx ref_ctx

				set func_name [lindex [info level 0] 0]
				set hash_name [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
				hash_init $hash_name ref_ctx
			}
			proc ${hash}_update {ctx messages} {
				upvar $ctx ref_ctx

				hash_update ref_ctx $messages
			}
			proc ${hash}_done {ctx} {
				upvar $ctx ref_ctx

				hash_done ref_ctx
			}
			proc ${hash}_process {messages} {

				set func_name [lindex [info level 0] 0]
				set hash_name [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
				hash_process $hash_name $messages
			}
	}
}


#new hash init
set rt_code [create_hash]

puts "load hashes successfully!"
