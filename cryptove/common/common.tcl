#===============================================================================
#common api for TCL
#
#common api
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#error_list 
#ret_code 
#cipher_direction 
#block_type 
#===============================================================================

package provide crypto 1.0.0


set error_list {
	ERR_ARGS "@wrong args"
	ERR_RUN  "@there is an error in running"
}
proc ret_code {func_name err_code err_str} {
	global error_list
	array set error_array $error_list
	return "error# $func_name $error_array($err_code): $err_str"
}

#
## cipher direction
## 'enc' for encrypt, 'dec' for decrypt
#
set cipher_direction {
	enc		00
	dec		01
}

set block_type {
	first_block		first_block
	middle_block	middle_block	
	last_block		last_block
}
