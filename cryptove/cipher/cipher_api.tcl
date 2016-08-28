#===============================================================================
#cipher api for TCL
#
#block cipher api 
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#aes_ecb_init
#aes_ecb_update
#aes_ecb_done
#...
#===============================================================================
#
package provide crypto 1.0.0

source [file join [file dirname [info script]] cipher_primitive.tcl]
source [file join [file dirname [info script]] cipher_mode.tcl]
source [file join [file dirname [info script]] ../common/common.tcl]

proc create_cipher {} {
	global cipher_list
	global mode_list
	foreach cipher [dict key $cipher_list] {
		foreach mode [dict key $mode_list] {
			proc ${cipher}_${mode}_init {ctx args} {
				upvar $ctx ref_ctx
				global mode_list

				set func_name [lindex [info level 0] 0]
				set cipher_name [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
				set func_name2 [string range $func_name [expr [string first _ $func_name] + 1] end]
				set mode_name [string range $func_name2 0 [expr [string first _ $func_name2] - 1]]
				set mode_func [dict get [dict get $mode_list ${mode_name}] init]

				set algs_list [concat ref_ctx $args]
				set algs_list [concat $cipher_name $algs_list]
				$mode_func $algs_list
			}

			proc ${cipher}_${mode}_update {ctx args} {
				upvar $ctx ref_ctx
				global mode_list

				set func_name [lindex [info level 0] 0]
				set cipher_name [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
				set func_name2 [string range $func_name [expr [string first _ $func_name] + 1] end]
				set mode_name [string range $func_name2 0 [expr [string first _ $func_name2] - 1]]
				set mode_func [dict get [dict get $mode_list ${mode_name}] update]

				set algs_list [concat ref_ctx $args]
				$mode_func $algs_list
			}

			proc ${cipher}_${mode}_done {ctx args} {
				upvar $ctx ref_ctx
				global mode_list

				set func_name [lindex [info level 0] 0]
				set cipher_name [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
				set func_name2 [string range $func_name [expr [string first _ $func_name] + 1] end]
				set mode_name [string range $func_name2 0 [expr [string first _ $func_name2] - 1]]
				set mode_func [dict get [dict get $mode_list ${mode_name}] done]

				set algs_list [concat ref_ctx $args]
				$mode_func $algs_list
			}

			proc ${cipher}_${mode}_process {args} {
				global mode_list

				set func_name [lindex [info level 0] 0]
				set cipher_name [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
				set func_name2 [string range $func_name [expr [string first _ $func_name] + 1] end]
				set mode_name [string range $func_name2 0 [expr [string first _ $func_name2] - 1]]
				set mode_func [dict get [dict get $mode_list ${mode_name}] process]

				set algs_list [concat $cipher_name $args]
				$mode_func $algs_list
			}

			#puts "${cipher}_${mode}_mode init success!"
		}
	}
}

#new cipher init
set rt_code [create_cipher]

puts "load ciphers successfully!"
