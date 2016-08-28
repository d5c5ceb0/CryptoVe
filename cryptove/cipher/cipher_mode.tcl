#===============================================================================
#cipher mode for TCL
#
#block cipher mode 
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
# register_mode 
# unregister_mode 
# mode_list 
# ecb_mode:     ecb_init     ecb_update     ecb_done     ecb_process
# cbc_mode:     cbc_init     cbc_update     cbc_done     cbc_process
# cfb_mode:     cfb_init     cfb_update     cfb_done     cfb_process
# ofb_mode:     ofb_init     ofb_update     ofb_done     ofb_process
# ctr_mode:     ctr_init     ctr_update     ctr_done     ctr_process
# xts_mode:     xts_init     xts_update     xts_done     xts_process
# cmac_mode:    cmac_init    cmac_update    cmac_done    cmac_process
# cbcmac_mode:  cbcmac_init  cbcmac_update  cbcmac_done  cbcmac_process
# xcbcmac_mode: xcbcmac_init xcbcmac_update xcbcmac_done xcbcmac_process
#===============================================================================
#
package provide crypto 1.0.0

source [file join [file dirname [info script]] cipher_primitive.tcl]
source [file join [file dirname [info script]] ../common/common.tcl]

#
## cipher mode lists
#
set mode_list {
	ecb {
		init 		ecb_init 
		update 		ecb_update 
		done 		ecb_done 
		process 	ecb_process
	}
	cbc {
		init 		cbc_init 
		update 		cbc_update 
		done 		cbc_done 
		process 	cbc_process
	}
	cfb {
		init 		cfb_init 
		update 		cfb_update 
		done 		cfb_done 
		process 	cfb_process
	}
	ofb {
		init 		ofb_init 
		update 		ofb_update 
		done 		ofb_done 
		process 	ofb_process
	}
	ctr {
		init 		ctr_init 
		update 		ctr_update 
		done 		ctr_done 
		process 	ctr_process
	}
	xts {
		init 		xts_init 
		update 		xts_update 
		done 		xts_done 
		process 	xts_process
	}
	cmac {
		init 		cmac_init 
		update 		cmac_update 
		done 		cmac_done 
		process 	cmac_process
	}
	cbcmac {
		init 		cbcmac_init 
		update 		cbcmac_update 
		done 		cbcmac_done 
		process 	cbcmac_process
	}
	xcbcmac {
		init 		xcbcmac_init 
		update 		xcbcmac_update 
		done 		xcbcmac_done 
		process 	xcbcmac_process
	}
}


##
######################################<ecb mode>#####################################
##

# ecb_init
# args_list - {alg ctx dir key}
# alg - the element in cipher_list
# dir - the element in cipher_direction
##
proc ecb_init {args_list} {
	global cipher_list
	global cipher_direction
	global block_type

	set alg [lindex $args_list 0]
	set ctx [lindex $args_list 1]
	set dir [lindex $args_list 2]
	set key [lindex $args_list 3]
	upvar $ctx ref_ctx
	
	# check alg
	if {[lsearch [dict keys $cipher_list] $alg] < 0} {
		return -code error [ret_code ecb_init ERR_ARGS "alg wrong!"]
	}  
	
	# check key length
	set klen [expr [string length $key]/2]
	if {[lsearch [lindex [dict get $cipher_list $alg] 1] $klen] < 0} {
      return -code error [ret_code ecb_init ERR_ARGS "key wrong!"]
  	}
  
	#check dir
	if {[lsearch [dict keys $cipher_direction] $dir] < 0} {
      return -code error [ret_code ecb_init ERR_ARGS "dir wrong!"]
	}
  
	dict set ref_ctx _alg         [lindex [dict get $cipher_list $alg] 0]
	dict set ref_ctx _mode        ecb
	dict set ref_ctx _dir         $dir
	dict set ref_ctx _key         $key
	dict set ref_ctx _block_len   [lindex [dict get $cipher_list $alg] 2]
	dict set ref_ctx _block_type  [dict get $block_type first_block]
}

##
# ecb_update
# args_list - {ctx messages}
##
proc ecb_update {args_list} {
	global block_type

	set ctx      [lindex $args_list 0]
	set messages [lindex $args_list 1]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error [ret_code ecb_update ERR_ARGS "ref_ctx wrong!"]
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set dir       [dict get $ref_ctx _dir]
	set block_len [dict get $ref_ctx _block_len]
	set mlen      [string length $messages]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {ecb} } {
		return -code error [ret_code ecb_update ERR_ARGS "ctx._mode wrong!"]
	}
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return -code error [ret_code ecb_update ERR_ARGS "ctx._block_type wrong!"]
	}
	
	#check length of the messages
  if {$mlen % ($block_len*2)} {
      return -code error [ret_code ecb_update ERR_ARGS "messages wrong!"]
  }
	
	set out ""
	for {set i 0} {$i < $mlen/($block_len*2)} {incr i 1} {
		set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
		append out [$cipher $dir $key $tmp_m]
	}
	
	dict set ref_ctx _block_type  [dict get $block_type middle_block]
	return $out
}

##
# ecb_done
# args_list - {ctx}
##
proc ecb_done {args_list} {
	global block_type

	set ctx [lindex $args_list 0]
	upvar $ctx ref_ctx
	
	dict set ref_ctx _block_type  [dict get $block_type last_block]
}

##
# ecb_process
# args_list - {alg dir key messages}
##
proc ecb_process {args_list} {
	set alg      [lindex $args_list 0]
	set dir      [lindex $args_list 1]
	set key      [lindex $args_list 2]
	set messages [lindex $args_list 3]
	
	ecb_init [list $alg ctx $dir $key]
	set out [ecb_update [list ctx $messages]]
	ecb_done [list ctx]
	
	return $out
}

##
######################################<cbc mode>#####################################
##

##
# cbc_init
# args_list - {alg ctx dir key iv}
# alg - the element in cipher_list
# dir - the element in cipher_direction
##
proc cbc_init {args_list} {
	global cipher_list
	global cipher_direction
	global block_type

	set alg [lindex $args_list 0]
	set ctx [lindex $args_list 1]
	set dir [lindex $args_list 2]
	set key [lindex $args_list 3]
	set iv  [lindex $args_list 4]
	upvar $ctx ref_ctx
	
	# check alg
	if {[lsearch [dict keys $cipher_list] $alg] < 0} {
		return -code error [ret_code cbc_init ERR_ARGS "alg wrong!"]
	}  
	
	# check key length
	set klen [expr [string length $key]/2]
	if {[lsearch [lindex [dict get $cipher_list $alg] 1] $klen] < 0} {
      return -code error [ret_code cbc_init ERR_ARGS "key wrong!"]
  }
  

	#check dir
	if {[lsearch [dict keys $cipher_direction] $dir] < 0} {
      return -code error [ret_code cbc_init ERR_ARGS "dir wrong!"]
	}
  
  # check iv length
  set block_len [lindex [dict get $cipher_list $alg] 2]
  if {[string length $iv]/2 != $block_len} {
      return -code error [ret_code cbc_init ERR_ARGS "iv wrong!"]
  }
  
	dict set ref_ctx _alg         [lindex [dict get $cipher_list $alg] 0]
	dict set ref_ctx _mode        cbc
	dict set ref_ctx _dir         $dir
	dict set ref_ctx _key         $key
	dict set ref_ctx _iv          $iv
	dict set ref_ctx _block_len   $block_len
	dict set ref_ctx _block_type  [dict get $block_type first_block]

}

##
# cbc_update
# args_list - {ctx messages}
##
proc cbc_update {args_list} {
	global block_type
	global cipher_direction
	
	set ctx      [lindex $args_list 0]
	set messages [lindex $args_list 1]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _iv]        ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error [ret_code cbc_update ERR_ARGS "ref_ctx wrong!"]
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set dir       [dict get $ref_ctx _dir]
	set iv        [dict get $ref_ctx _iv]
	set block_len [dict get $ref_ctx _block_len]
	set mlen      [string length $messages]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {cbc} } {
		return -code error [ret_code cbc_update ERR_ARGS "ctx._mode wrong!"]
	}
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return -code error [ret_code cbc_update ERR_ARGS "ctx._block_type wrong!"]
	}
	
	#check length of the messages
  if {$mlen % ($block_len*2)} {
      return -code error [ret_code cbc_update ERR_ARGS "messages wrong!"]
  }
	
	set out ""
  #00¼ÓÃÜ 01½âÃÜ
  if {$dir == [lindex $cipher_direction 0]} {
      for {set i 0} {$i < $mlen/($block_len*2)} {incr i 1} {
          set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
          set tmp_m [xor $tmp_m $iv]
          set iv [$cipher $dir $key $tmp_m]
          append out $iv
      }
  } else {
      for {set i 0} {$i < $mlen/($block_len*2)} {incr i 1} {
          set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
          set tmp_iv $tmp_m
          set tmp_m [$cipher $dir $key $tmp_m]
          append out [xor $tmp_m $iv]
          set iv $tmp_iv
      }
  }

	dict set ref_ctx _iv $iv
	dict set ref_ctx _block_type  [dict get $block_type middle_block]
  return $out
  
}

##
# cbc_done
# args_list - {ctx}
##
proc cbc_done {args_list} {
	global block_type

	set ctx [lindex $args_list 0]
	upvar $ctx ref_ctx
	dict set ref_ctx _block_type  [dict get $block_type last_block]
}

##
# cbc_process
# args_list - {alg dir key iv messages}
##
proc cbc_process {args_list} {

	set alg      [lindex $args_list 0]
	set dir      [lindex $args_list 1]
	set key      [lindex $args_list 2]
	set iv       [lindex $args_list 3]
	set messages [lindex $args_list 4]
	
	cbc_init [list $alg ctx $dir $key $iv]
	set out [cbc_update [list ctx $messages]]
	cbc_done [list ctx]

	return $out
}


##
######################################<cfb mode>#####################################
##

##
# cfb_init
# args_list - {alg ctx dir key iv}
# alg - the element in cipher_list
# dir - the element in cipher_direction
##
proc cfb_init {args_list} {
	global cipher_list
	global block_type
	global cipher_direction

	set alg [lindex $args_list 0]
	set ctx [lindex $args_list 1]
	set dir [lindex $args_list 2]
	set key [lindex $args_list 3]
	set iv  [lindex $args_list 4]
	upvar $ctx ref_ctx
	
	# check alg
	if {[lsearch [dict keys $cipher_list] $alg] < 0} {
		return -code error [ret_code cfb_init ERR_ARGS "alg wrong!"]
	}  
	
	# check key length
	set klen [expr [string length $key]/2]
	if {[lsearch [lindex [dict get $cipher_list $alg] 1] $klen] < 0} {
      return -code error [ret_code cfb_init ERR_ARGS "key wrong!"]
  }
  
	#check dir
	if {[lsearch [dict keys $cipher_direction] $dir] < 0} {
      return -code error [ret_code cfb_init ERR_ARGS "dir wrong!"]
	}
  
  # check iv length
  set block_len [lindex [dict get $cipher_list $alg] 2]
  if {[string length $iv]/2 != $block_len} {
      return -code error [ret_code cfb_init ERR_ARGS "iv wrong!"]
  }
  
	dict set ref_ctx _alg         [lindex [dict get $cipher_list $alg] 0]
	dict set ref_ctx _mode        cfb
	dict set ref_ctx _dir         $dir
	dict set ref_ctx _key         $key
	dict set ref_ctx _iv          $iv
	dict set ref_ctx _block_len   $block_len
	dict set ref_ctx _block_type  [dict get $block_type first_block]
}

##
# cfb_update
# args_list - {ctx messages}
##
proc cfb_update {args_list} {
	global block_type
	global cipher_direction
	
	set ctx      [lindex $args_list 0]
	set messages [lindex $args_list 1]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _iv]        ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error [ret_code cfb_update ERR_ARGS "ref_ctx wrong!"]
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set dir       [dict get $ref_ctx _dir]
	set iv        [dict get $ref_ctx _iv]
	set block_len [dict get $ref_ctx _block_len]
	set mlen      [string length $messages]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {cfb} } {
		return -code error [ret_code cfb_update ERR_ARGS "ctx._mode wrong!"]
	}
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return -code error [ret_code cfb_update ERR_ARGS "ctx._block_type wrong!"]
	}
	
	#check length of the messages
  if {$mlen % ($block_len*2)} {
	  puts $messages
      return -code error [ret_code cfb_update ERR_ARGS "messages wrong!"]
  }

	set out ""
	if {$dir == [lindex [dict keys $cipher_direction] 0]} {
		for {set i 0} {$i < $mlen/($block_len*2)} {incr i 1} {
			set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
			set t [$cipher $dir $key $iv]
			set tmp_m [xor $t $tmp_m]
			set iv $tmp_m
			append out $tmp_m
		}
	} else {
		set dir2 [lindex [dict keys $cipher_direction] 0]
		for {set i 0} {$i < $mlen/($block_len*2)} {incr i 1} {
			set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
			set t [$cipher $dir2 $key $iv]
			set iv $tmp_m
			set tmp_m [xor $t $tmp_m]
			append out $tmp_m
		}
	}

	dict set ref_ctx _iv $iv
	dict set ref_ctx _block_type  [dict get $block_type middle_block]
    return $out
}

##
# cfb_done
# args_list - {ctx}
##
proc cfb_done {args_list} {
	global block_type

	set ctx [lindex $args_list 0]
	upvar $ctx ref_ctx
	dict set ref_ctx _block_type  [dict get $block_type last_block]
}

##
# cfb_process
# args_list - {alg fbs dir key iv messages}
##
proc cfb_process {args_list} {
	set alg      [lindex $args_list 0]
	set dir      [lindex $args_list 1]
	set key      [lindex $args_list 2]
	set iv       [lindex $args_list 3]
	set messages [lindex $args_list 4]
	
	cfb_init [list $alg ctx $dir $key $iv]
	set out [cfb_update [list ctx $messages]]
	cfb_done [list ctx]

	return $out
}

##
######################################<ofb mode>#####################################
##

##
# ofb_init
# args_list - {alg ctx dir key iv}
# alg - the element in cipher_list
# dir - the element in cipher_direction
##
proc ofb_init {args_list} {
	global cipher_list
	global cipher_direction
	global block_type

	set alg [lindex $args_list 0]
	set ctx [lindex $args_list 1]
	set dir [lindex $args_list 2]
	set key [lindex $args_list 3]
	set iv  [lindex $args_list 4]
	upvar $ctx ref_ctx
	
	# check alg
	if {[lsearch [dict keys $cipher_list] $alg] < 0} {
		return -code error [ret_code ofb_init ERR_ARGS "alg wrong!"]
	}  
	
	# check key length
	set klen [expr [string length $key]/2]
	if {[lsearch [lindex [dict get $cipher_list $alg] 1] $klen] < 0} {
      return -code error [ret_code ofb_init ERR_ARGS "key wrong!"]
  }
  
	#check dir
	if {[lsearch [dict keys $cipher_direction] $dir] < 0} {
      return -code error [ret_code ofb_init ERR_ARGS "dir wrong!"]
	}

  # check iv length
  set block_len [lindex [dict get $cipher_list $alg] 2]
  if {[string length $iv]/2 != $block_len} {
      return -code error [ret_code ofb_init ERR_ARGS "iv wrong!"]
  }
  
	dict set ref_ctx _alg         [lindex [dict get $cipher_list $alg] 0]
	dict set ref_ctx _mode        ofb
	dict set ref_ctx _dir         [lindex [dict keys $cipher_direction] 0]
	dict set ref_ctx _key         $key
	dict set ref_ctx _iv          $iv
	dict set ref_ctx _block_len   $block_len
	dict set ref_ctx _block_type  [dict get $block_type first_block]
}

##
# ofb_update
# args_list - {ctx messages}
##
proc ofb_update {args_list} {
	global block_type
	global cipher_direction
	
	set ctx      [lindex $args_list 0]
	set messages [lindex $args_list 1]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _iv]        ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error [ret_code ofb_update ERR_ARGS "ref_ctx wrong!"]
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set dir       [dict get $ref_ctx _dir]
	set iv        [dict get $ref_ctx _iv]
	set block_len [dict get $ref_ctx _block_len]
	set mlen      [string length $messages]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {ofb} } {
		return -code error [ret_code ofb_update ERR_ARGS "ctx._mode wrong!"]
	}
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return -code error [ret_code ofb_update ERR_ARGS "ctx._block_type wrong!"]
	}
	
	#check length of the messages
  if {$mlen % ($block_len*2)} {
	  puts $messages
      return -code error [ret_code cfb_update ERR_ARGS "messages wrong!"]
  }

	set out ""
	for {set i 0} {$i < $mlen/($block_len*2)} {incr i 1} {
		set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
		set iv [$cipher $dir $key $iv]
		append out [xor $iv $tmp_m]
	}

	dict set ref_ctx _iv $iv
	dict set ref_ctx _block_type  [dict get $block_type middle_block]
  return $out
}

##
# ofb_done
# args_list - {ctx}
##
proc ofb_done {args_list} {
	global block_type

	set ctx [lindex $args_list 0]
	upvar $ctx ref_ctx
	dict set ref_ctx _block_type  [dict get $block_type last_block]
}

##
# ofb_process
# args_list - {alg dir key iv messages}
##
proc ofb_process {args_list} {
	set alg       [lindex $args_list 0]
	set dir       [lindex $args_list 1]
	set key       [lindex $args_list 2]
	set iv        [lindex $args_list 3]
	set messages  [lindex $args_list 4]
	
	ofb_init [list $alg ctx $dir $key $iv]
	set out [ofb_update [list ctx $messages]]
	ofb_done [list ctx]
	
	return $out
}


##
######################################<ctr mode>#####################################
##

##
# ctr_init
# args_list - {alg ctx dir key iv}
# alg - the element in cipher_list
# dir - the element in cipher_direction
##
proc ctr_init {args_list} {
	global cipher_list
	global block_type
	global cipher_direction

	set alg [lindex $args_list 0]
	set ctx [lindex $args_list 1]
	set dir [lindex $args_list 2]
	set key [lindex $args_list 3]
	set iv  [lindex $args_list 4]
	upvar $ctx ref_ctx
	
	# check alg
	if {[lsearch [dict keys $cipher_list] $alg] < 0} {
		return -code error [ret_code ctr_init ERR_ARGS "alg wrong!"]
	}  
	
	# check key length
	set klen [expr [string length $key]/2]
	if {[lsearch [lindex [dict get $cipher_list $alg] 1] $klen] < 0} {
      return -code error [ret_code ctr_init ERR_ARGS "key wrong!"]
  }
  
	#check dir
	if {[lsearch [dict keys $cipher_direction] $dir] < 0} {
      return -code error [ret_code ctr_init ERR_ARGS "dir wrong!"]
	}
  
  # check iv length
  set block_len [lindex [dict get $cipher_list $alg] 2]
  if {[string length $iv]/2 != $block_len} {
      return -code error [ret_code ctr_init ERR_ARGS "iv wrong!"]
  }
  
	dict set ref_ctx _alg         [lindex [dict get $cipher_list $alg] 0]
	dict set ref_ctx _mode        ctr
	dict set ref_ctx _dir         [lindex [dict keys $cipher_direction] 0]
	dict set ref_ctx _key         $key
	dict set ref_ctx _iv          $iv
	dict set ref_ctx _block_len   $block_len
	dict set ref_ctx _block_type  [dict get $block_type first_block]
}

##
# ctr_update
# args_list - {ctx messages}
##
proc ctr_update {args_list} {
	global block_type
	global cipher_direction
	
	set ctx      [lindex $args_list 0]
	set messages [lindex $args_list 1]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _iv]        ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error [ret_code ctr_update ERR_ARGS "ref_ctx wrong!"]
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set dir       [dict get $ref_ctx _dir]
	set iv        [dict get $ref_ctx _iv]
	set block_len [dict get $ref_ctx _block_len]
	set mlen      [string length $messages]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {ctr} } {
		return -code error [ret_code ctr_update ERR_ARGS "ctx._mode wrong!"]
	}
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return -code error [ret_code ctr_update ERR_ARGS "ctx._block_type wrong!"]
	}
	
	#check length of the messages
  if {$mlen == 0} {
      return -code error [ret_code ctr_update ERR_ARGS "messages wrong!"]
  }  
	set rlen [expr $mlen%($block_len*2)]
	
	set out ""
	for {set i 0} {$i < $mlen/($block_len*2)} {incr i 1} {
		set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
		set t [$cipher $dir $key $iv]
		append out [xor $t $tmp_m]
		#set iv [endian $iv]
		set iv [add $iv 01]
		set iv [string repeat 00 [expr $block_len - [string length $iv]/2]]$iv
		##set iv [endian $iv]
	}
	
	if {$rlen} {
		set t [$cipher $dir $key $iv]
		set tmp_m [string range $messages [expr $i*$block_len*2] end]
		append out [xor [string range $t 0 [expr $rlen-1]] $tmp_m]
		dict set ref_ctx _block_type  [dict get $block_type last_block]
		return $out
	}
	
	dict set ref_ctx _iv $iv
	dict set ref_ctx _block_type  [dict get $block_type middle_block]
  return $out
}

##
# ctr_done
# args_list - {ctx}
##
proc ctr_done {args_list} {
	global block_type

	set ctx [lindex $args_list 0]
	upvar $ctx ref_ctx
	dict set ref_ctx _block_type  [dict get $block_type last_block]
}

##
# ctr_process
# args_list - {alg dir key iv messages}
##
proc ctr_process {args_list} {
	set alg       [lindex $args_list 0]
	set dir       [lindex $args_list 1]
	set key       [lindex $args_list 2]
	set iv        [lindex $args_list 3]
	set messages  [lindex $args_list 4]
	
	ctr_init [list $alg ctx $dir $key $iv]
	set out [ctr_update [list ctx $messages]]
	ctr_done [list ctx]
	
	return $out
}


##
######################################<xts mode>#####################################
##

##
# xts_init
# args_list - {alg ctx dir key iv}
# alg - the element in cipher_list
# dir - the element in cipher_direction
##
proc xts_init {args_list} {
	global cipher_list
	global cipher_direction
	global block_type

	set alg [lindex $args_list 0]
	set ctx [lindex $args_list 1]
	set dir [lindex $args_list 2]
	set key [lindex $args_list 3]
	set iv  [lindex $args_list 4]
	upvar $ctx ref_ctx
	
	# check alg
	if {[lsearch [dict keys $cipher_list] $alg] < 0} {
		return -code error [ret_code xts_init ERR_ARGS "alg wrong!"]
	}  
	
	# check key length
	set klen [expr [string length $key]/2/2]
	if {[lsearch [lindex [dict get $cipher_list $alg] 1] $klen] < 0} {
      return -code error [ret_code xts_init ERR_ARGS "key wrong!"]
  }
  
	#check dir
	if {[lsearch [dict keys $cipher_direction] $dir] < 0} {
      return -code error [ret_code xts_init ERR_ARGS "dir wrong!"]
	}
  
  # check iv length
  set block_len [lindex [dict get $cipher_list $alg] 2]
  if {[string length $iv]/2 != $block_len} {
      return -code error [ret_code xts_init ERR_ARGS "iv wrong!"]
  }

  	set encrypt [lindex [dict keys $cipher_direction] 0]
	set cipher [lindex [dict get $cipher_list $alg] 0]
    set key1 [string range $key 0 [expr $klen*2-1]]
	set key2 [string range $key [expr $klen*2] end]
	set iv [$cipher $encrypt $key2 $iv]
	
    dict set ref_ctx _alg         $cipher
	dict set ref_ctx _mode        xts
	dict set ref_ctx _dir         $dir
	dict set ref_ctx _key         $key1
	dict set ref_ctx _xex_key     $key2
	dict set ref_ctx _iv          $iv
	dict set ref_ctx _block_len   $block_len
	dict set ref_ctx _block_type  [dict get $block_type first_block]

}

proc xts_mult_x {tweak} {

    set size [string length $tweak]
    if {$size != 32} {
        return -code error "[xts_mult_x] length error, need to be 16 bytes."
    }

    set result ""
    for {set x 0;set t 0} {$x < $size} {incr x 2} {
        set tempT [string range $tweak $x [expr $x+1]]
        set tt [format %02x [expr 0x$tempT >> 7]]
        set tempT [format %02x [expr ((0x$tempT << 1) | 0x$t) & 0xFF]]
        append result $tempT
        set t $tt
    }
    if {[expr 0x$tt]} {
        set tempT [string range $result 0 1]
        set tempT [format %02x [expr 0x$tempT ^ 0x87]]
        set result $tempT[string range $result 2 end]
    }

    return $result
}

##
# xts_update
# args_list - {ctx messages}
##
proc xts_update {args_list} {
	global block_type
	global cipher_direction
	
	set ctx      [lindex $args_list 0]
	set messages [lindex $args_list 1]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _iv]        ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error [ret_code xts_update ERR_ARGS "ref_ctx wrong!"]
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set dir       [dict get $ref_ctx _dir]
	set iv        [dict get $ref_ctx _iv]
	set block_len [dict get $ref_ctx _block_len]
	set mlen      [string length $messages]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {xts} } {
		return -code error [ret_code xts_update ERR_ARGS "ctx._mode wrong!"]
	}
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return -code error [ret_code xts_update ERR_ARGS "ctx._block_type wrong!"]
	}
	
	#check length of the messages
	  if {$mlen < ($block_len*2)} {
	      return -code error [ret_code xts_update ERR_ARGS "messages wrong!"]
	  }
	  
	set rlen [expr $mlen%($block_len*2)]
	if {$rlen} {
		set qlen [expr $mlen - ($block_len*2) - $rlen]
	} else {
		set qlen $mlen
	}
	
	set out ""
	for {set i 0} {$i < $qlen/($block_len*2)} {incr i 1} {
		set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
		set tmp_m [xor $tmp_m $iv]
		set tmp_m [$cipher $dir $key $tmp_m]
		append out [xor $tmp_m $iv]
		set iv [xts_mult_x $iv]
	}

	if {$rlen} {
		#enc
		if {$dir == [lindex [dict keys $cipher_direction] 0]} {
			set iv_1 $iv
			set iv_2 [xts_mult_x $iv]
		} else {
			set iv_2 $iv
			set iv_1 [xts_mult_x $iv]
		}
		set tmp_m [string range $messages $qlen [expr $qlen+$block_len*2-1]]
		set tmp_m [xor $tmp_m $iv_1]
		set tmp_m [$cipher $dir $key $tmp_m]
		set tmp_m [xor $tmp_m $iv_1]
		set m_1 $tmp_m
		#set iv [xts_mult_x $iv]
		set tmp_m [string range $messages [expr $qlen+$block_len*2] end][string range $tmp_m $rlen end]
		set tmp_m [xor $tmp_m $iv_2]
		set tmp_m [$cipher $dir $key $tmp_m]
		append out [xor $tmp_m $iv_2]
		append out [string range $m_1 0 [expr $rlen-1]]
		
		dict set ref_ctx _block_type  [dict get $block_type last_block]
		return $out
	}
	
	dict set ref_ctx _iv $iv
	dict set ref_ctx _block_type  [dict get $block_type middle_block]
    return $out
}

##
# xts_done
# args_list - {ctx}
##
proc xts_done {args_list} {
	global block_type

	set ctx [lindex $args_list 0]
	upvar $ctx ref_ctx
	dict set ref_ctx _block_type  [dict get $block_type last_block]
}

##
# xts_process
# args_list - {alg dir key iv messages}
##
proc xts_process {args_list} {
	set alg       [lindex $args_list 0]
	set dir       [lindex $args_list 1]
	set key       [lindex $args_list 2]
	set iv        [lindex $args_list 3]
	set messages  [lindex $args_list 4]
	
	xts_init [list $alg ctx $dir $key $iv]
	set out [xts_update [list ctx $messages]]
	xts_done [list ctx]
	
	return $out
}

######################################<cbcmac mode>#####################################
##

##
# cbcmac_init
# args_list - {alg ctx key}
# alg - the element in cipher_list
# dir - the element in cipher_direction
##
proc cbcmac_init {args_list} {
	global cipher_list
	global cipher_direction
	global block_type

	set alg [lindex $args_list 0]
	set ctx [lindex $args_list 1]
	set key [lindex $args_list 2]
	upvar $ctx ref_ctx
	
	# check alg
	if {[lsearch [dict keys $cipher_list] $alg] < 0} {
		return -code error [ret_code cbcmac_init ERR_ARGS "alg wrong!"]
	}  
	
	# check key length
	set klen [expr [string length $key]/2]
	if {[lsearch [lindex [dict get $cipher_list $alg] 1] $klen] < 0} {
      return -code error [ret_code cbcmac_init ERR_ARGS "key wrong!"]
    }

  	set encrypt [lindex [dict key $cipher_direction] 0]
  	set block_len [lindex [dict get $cipher_list $alg] 2]
  	set iv [string repeat 00 $block_len]
  
	dict set ref_ctx _alg         [lindex [dict get $cipher_list $alg] 0]
	dict set ref_ctx _mode        cbcmac
	dict set ref_ctx _dir         $encrypt
	dict set ref_ctx _key         $key
	dict set ref_ctx _iv          $iv
	dict set ref_ctx _block_len   $block_len
	dict set ref_ctx _block_type  [dict get $block_type first_block]
	
}

##
# cbcmac_update
# args_list - {ctx messages}
##
proc cbcmac_update {args_list} {
	global block_type
	global cipher_direction
	
	set ctx      [lindex $args_list 0]
	set messages [lindex $args_list 1]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _iv]        ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error [ret_code cbcmac_update ERR_ARGS "ref_ctx wrong!"]
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set dir       [dict get $ref_ctx _dir]
	set iv        [dict get $ref_ctx _iv]
	set block_len [dict get $ref_ctx _block_len]
	set mlen      [string length $messages]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {cbcmac} } {
		return -code error [ret_code cbcmac_update ERR_ARGS "ctx._mode wrong!"]
	}
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return -code error [ret_code cbcmac_update ERR_ARGS "ctx._block_type wrong!"]
	}
	
	#check length of the messages
  if {$mlen == 0} {
      return
  }
	  
	#check length of the messages
	  if {$mlen % ($block_len*2)} {
	      return -code error [ret_code cbc_update ERR_ARGS "messages wrong!"]
	  }
  
	for {set i 0} {$i < $mlen/($block_len*2)} {incr i 1} {
		set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
		set tmp_m [xor $tmp_m $iv]
		set iv [$cipher $dir $key $tmp_m]
	}

	dict set ref_ctx _iv $iv
	dict set ref_ctx _block_type  [dict get $block_type middle_block]
    return
}

##
# cbcmac_done
# args_list - {ctx}
##
proc cbcmac_done {args_list} {
	global block_type

	set ctx [lindex $args_list 0]
	upvar $ctx ref_ctx
	
	if {![dict exists $ref_ctx _block_type]||
	    ![dict exists $ref_ctx _iv]  } {
		return -code error [ret_code cbcmac_done ERR_ARGS "ref_ctx wrong!"]
	}
	
	if {[dict get $ref_ctx _block_type] == [dict get $block_type first_block] } {
	  #TODO
	  set iv [$cipher $dir $key $iv]
	  dict set ref_ctx _iv $iv
	  dict set ref_ctx _block_type  [dict get $block_type last_block]
	  return $iv
	}
	
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return [dict get $ref_ctx _iv]
	}
	
	dict set ref_ctx _block_type  [dict get $block_type last_block]
	return [dict get $ref_ctx _iv]
}

##
# cbcmac_process
# args_list - {alg key messages}
##
proc cbcmac_process {args_list} {

	set alg      [lindex $args_list 0]
	set key      [lindex $args_list 1]
	set messages [lindex $args_list 2]
	
	cbcmac_init [list $alg ctx $key]
	cbcmac_update [list ctx $messages]
	set out [cbcmac_done [list ctx]]

	return $out

}
##
######################################<cmac mode>#####################################
##

##
# cmac_init
# args_list - {ctx alg key}
# alg - the element in cipher_list
# dir - the element in cipher_direction
##
proc cmac_init {args_list} {
	global cipher_list
	global cipher_direction
	global block_type

	set alg [lindex $args_list 0]
	set ctx [lindex $args_list 1]
	set key [lindex $args_list 2]
	upvar $ctx ref_ctx
	
	# check alg
	if {[lsearch [dict keys $cipher_list] $alg] < 0} {
		return -code error [ret_code cmac_init ERR_ARGS "alg wrong!"]
	}  
	
	# check key length
	set klen [expr [string length $key]/2]
	if {[lsearch [lindex [dict get $cipher_list $alg] 1] $klen] < 0} {
      return -code error [ret_code cmac_init ERR_ARGS "key wrong!"]
    }

  	set encrypt [lindex [dict key $cipher_direction] 0]
  set block_len [lindex [dict get $cipher_list $alg] 2]
  set iv [string repeat 00 $block_len]
  
  if {$block_len == 16} {
  	set rb [string repeat 00 15]87
  } elseif {$block_len == 8} {
		set rb [string repeat 00 7]1b
  } else {
  	return -code error [ret_code cmac_init ERR_ARGS "block length error!"]
  }
  set cipher [lindex [dict get $cipher_list $alg] 0]
  set key0 [$cipher $encrypt $key [string repeat 00 $block_len]]
	if {!([expr 0x[string range $key0 0 1]] & 0x80)} {
		set key1 [sft L $key0 1]
	} else {
		set tlen [expr $block_len*2-1]
		set key1 [xor [string range [sft L $key0 1] end-$tlen end] $rb]
	}
	if {!([expr 0x[string range $key1 0 1]] & 0x80)} {
		set key2 [sft L $key1 1]
	} else {
		set tlen [expr $block_len*2-1]
		set key2 [xor [string range [sft L $key1 1] end-$tlen end] $rb]
	}
  
	dict set ref_ctx _alg         $cipher
	dict set ref_ctx _mode        cmac
	dict set ref_ctx _dir         $encrypt
	dict set ref_ctx _key         $key
	dict set ref_ctx _cmac_key1   [string range $key1 0 [expr $block_len*2-1]]
	dict set ref_ctx _cmac_key2   [string range $key2 0 [expr $block_len*2-1]]
	dict set ref_ctx _iv          $iv
	dict set ref_ctx _block_len   $block_len
	dict set ref_ctx _block_type  [dict get $block_type first_block]
}

##
# cmac_update
# args_list - {ctx messages}
##
proc cmac_update {args_list} {
	global block_type
	global cipher_direction
	
	set ctx      [lindex $args_list 0]
	set messages [lindex $args_list 1]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _cmac_key2] ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _iv]        ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error [ret_code cmac_update ERR_ARGS "ref_ctx wrong!"]
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set key2      [dict get $ref_ctx _cmac_key2]
	set dir       [dict get $ref_ctx _dir]
	set iv        [dict get $ref_ctx _iv]
	set block_len [dict get $ref_ctx _block_len]
	set mlen      [string length $messages]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {cmac} } {
		return -code error [ret_code cmac_update ERR_ARGS "ctx._mode wrong!"]
	}
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return -code error [ret_code cmac_update ERR_ARGS "ctx._block_type wrong!"]
	}
  
  #check length of the messages
	  if {$mlen == 0} {
	      return
	  }
	  
	set rlen [expr $mlen%($block_len*2)]
	
	for {set i 0} {$i < $mlen/($block_len*2)} {incr i 1} {
		set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
		set tmp_m [xor $tmp_m $iv]
		set iv [$cipher $dir $key $tmp_m]
	}

	if {$rlen} {
		set tmp_m [string range $messages [expr $i*$block_len*2] end]
		set tmp_m ${tmp_m}80[string repeat 00 [expr $block_len-$rlen/2 - 1]]
		set tmp_m [xor [xor $tmp_m $iv] $key2]
		set iv [$cipher $dir $key $tmp_m]
		
		dict set ref_ctx _iv $iv
		dict set ref_ctx _block_type  [dict get $block_type last_block]
		return
	}
	
	dict set ref_ctx _iv $iv
	dict set ref_ctx _block_type  [dict get $block_type middle_block]
  return
}

##
# cmac_done
# args_list - {ctx}
##
proc cmac_done {args_list} {
	global block_type
	global cipher_direction
	
	set ctx [lindex $args_list 0]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _cmac_key1]       ||
	    ![dict exists $ref_ctx _cmac_key2]       ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _iv]        ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error {Error(cmac_done): the arg ctx error.}
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set key1      [dict get $ref_ctx _cmac_key1]
	set key2      [dict get $ref_ctx _cmac_key2]
	set dir       [dict get $ref_ctx _dir]
	set iv        [dict get $ref_ctx _iv]
	set block_len [dict get $ref_ctx _block_len]
	
	set encrypt [lindex [dict key $cipher_direction] 0]
	set decrypt [lindex [dict key $cipher_direction] 1]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {cmac} } {
		return -code error {Error(cmac_done): the _mode in ctx error.}
	}
	
	if {[dict get $ref_ctx _block_type] == [dict get $block_type first_block] } {
		set tmp_m 80[string repeat 00 [expr $block_len-1]]
		set tmp_m [xor [xor $iv $tmp_m] $key2]
	  set iv [$cipher $dir $key $tmp_m]
	  dict set ref_ctx _iv $iv
	  dict set ref_ctx _block_type  [dict get $block_type last_block]
	  return $iv
	}
	
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return [dict get $ref_ctx _iv]
	}
	
	set iv [$cipher $decrypt $key $iv]
	set tmp_m [xor $iv $key1]
	set iv [$cipher $dir $key $tmp_m]
	dict set ref_ctx _iv $iv
	
	dict set ref_ctx _block_type  [dict get $block_type last_block]
	return $iv
}

##
# cmac_process
# args_list - {alg key messages}
##
proc cmac_process {args_list} {

	set alg      [lindex $args_list 0]
	set key      [lindex $args_list 1]
	set messages [lindex $args_list 2]
	
	cmac_init [list $alg ctx $key]
	cmac_update [list ctx $messages]
	set out [cmac_done [list ctx]]

	return $out

}
##
######################################<xcbcmac mode>#####################################
##

##
# xcbcmac_init
# args_list - {alg ctx key}
# alg - the element in cipher_list
# dir - the element in cipher_direction
##
proc xcbcmac_init {args_list} {
	global cipher_list
	global cipher_direction
	global block_type

	set alg [lindex $args_list 0]
	set ctx [lindex $args_list 1]
	set key [lindex $args_list 2]
	upvar $ctx ref_ctx
	
	# check alg
	if {[lsearch [dict keys $cipher_list] $alg] < 0} {
		return -code error [ret_code xcbcmac_init ERR_ARGS "alg wrong!"]
	}  
	
	# check key length
	set klen [expr [string length $key]/2]
	if {[lsearch [lindex [dict get $cipher_list $alg] 1] $klen] < 0} {
      return -code error [ret_code xcbcmac_init ERR_ARGS "key wrong!"]
    }

  set encrypt [lindex [dict key $cipher_direction] 0]
  set block_len [lindex [dict get $cipher_list $alg] 2]
  set iv [string repeat 00 $block_len]
  
  set str1 [string repeat 01 $block_len]
	set str2 [string repeat 02 $block_len]
	set str3 [string repeat 03 $block_len]
  
	set cipher [lindex [dict get $cipher_list $alg] 0]
    set key1 [$cipher $encrypt $key $str1]
	set key2 [$cipher $encrypt $key $str2]
	set key3 [$cipher $encrypt $key $str3]
  
	dict set ref_ctx _alg         $cipher
	dict set ref_ctx _mode        xcbcmac
	dict set ref_ctx _dir         $encrypt
	dict set ref_ctx _key         $key
	dict set ref_ctx _xcbcmac_key1 $key1
	dict set ref_ctx _xcbcmac_key2 $key2
	dict set ref_ctx _xcbcmac_key3 $key3
	dict set ref_ctx _iv          $iv
	dict set ref_ctx _block_len   $block_len
	dict set ref_ctx _block_type  [dict get $block_type first_block]

}

##
# xcbcmac_update
# args_list - {ctx messages}
##
proc xcbcmac_update {args_list} {
	global block_type
	global algo_direct
	
	set ctx      [lindex $args_list 0]
	set messages [lindex $args_list 1]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _iv]        ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error [ret_code xcbcmac_update ERR_ARGS "ref_ctx wrong!"]
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set key1      [dict get $ref_ctx _xcbcmac_key1]
	set key2      [dict get $ref_ctx _xcbcmac_key2]
	set key3      [dict get $ref_ctx _xcbcmac_key3]
	set dir       [dict get $ref_ctx _dir]
	set iv        [dict get $ref_ctx _iv]
	set block_len [dict get $ref_ctx _block_len]
	set mlen      [string length $messages]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {xcbcmac} } {
		return -code error [ret_code xcbcmac_update ERR_ARGS "ctx._mode wrong!"]
	}
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return -code error [ret_code xcbcmac_update ERR_ARGS "ctx._block_type wrong!"]
	}
  
  #check length of the messages
	  if {$mlen == 0} {
	      return
	  }
	  
	set rlen [expr $mlen%($block_len*2)]
	
	for {set i 0} {$i < $mlen/($block_len*2)} {incr i 1} {
		set tmp_m [string range $messages [expr $i*$block_len*2] [expr ($i+1)*$block_len*2-1]]
		set tmp_m [xor $tmp_m $iv]
		set iv [$cipher $dir $key1 $tmp_m]
	}

	if {$rlen} {
		set tmp_m [string range $messages [expr $i*$block_len*2] end]
		set tmp_m ${tmp_m}80[string repeat 00 [expr $block_len-$rlen/2 - 1]]
		set tmp_m [xor [xor $tmp_m $iv] $key3]
		set iv [$cipher $dir $key1 $tmp_m]
		
		dict set ref_ctx _iv $iv
		dict set ref_ctx _block_type  [dict get $block_type last_block]
		return
	}
	
	dict set ref_ctx _iv $iv
	dict set ref_ctx _block_type  [dict get $block_type middle_block]
  return
}

##
# xcbcmac_done
# args_list - {ctx}
##
proc xcbcmac_done {args_list} {
	global block_type
	global cipher_direction
	
	set ctx  [lindex $args_list 0]
	upvar $ctx ref_ctx
	
	#check ctx
	if {![dict exists $ref_ctx _alg]       || 
	    ![dict exists $ref_ctx _key]       ||
	    ![dict exists $ref_ctx _mode]      ||
	    ![dict exists $ref_ctx _dir]       ||
	    ![dict exists $ref_ctx _iv]        ||
	    ![dict exists $ref_ctx _block_len] ||
	    ![dict exists $ref_ctx _block_type] } {
		return -code error {Error(xcbcmac_done): the arg ctx error.}
	}
	
	set cipher    [dict get $ref_ctx _alg]
	set key       [dict get $ref_ctx _key]
	set key1      [dict get $ref_ctx _xcbcmac_key1]
	set key2      [dict get $ref_ctx _xcbcmac_key2]
	set key3      [dict get $ref_ctx _xcbcmac_key3]
	set dir       [dict get $ref_ctx _dir]
	set iv        [dict get $ref_ctx _iv]
	set block_len [dict get $ref_ctx _block_len]
	
	set encrypt [lindex [dict key $cipher_direction] 0]
	set decrypt [lindex [dict key $cipher_direction] 1]
	
	#check mode
	if {[dict get $ref_ctx _mode] != {xcbcmac} } {
		return -code error {Error(xcbcmac_done): the _mode in ctx error.}
	}
	
	if {[dict get $ref_ctx _block_type] == [dict get $block_type first_block] } {
		set tmp_m 80[string repeat 00 [expr $block_len-1]]
		set tmp_m [xor [xor $iv $tmp_m] $key3]
	  set iv [$cipher $dir $key1 $tmp_m]
	  dict set ref_ctx _iv $iv
	  dict set ref_ctx _block_type  [dict get $block_type last_block]
	  return $iv
	}
	
	if {[dict get $ref_ctx _block_type] == [dict get $block_type last_block] } {
		return [dict get $ref_ctx _iv]
	}
	
	set iv [$cipher $decrypt $key1 $iv]
	set tmp_m [xor $iv $key2]
	set iv [$cipher $dir $key1 $tmp_m]
	dict set ref_ctx _iv $iv
	
	dict set ref_ctx _block_type  [dict get $block_type last_block]
	return $iv
}

##
# xcbcmac_process
# args_list - {alg key messages}
##
proc xcbcmac_process {args_list} {

	set alg      [lindex $args_list 0]
	set key      [lindex $args_list 1]
	set messages [lindex $args_list 2]
	
	xcbcmac_init [list $alg ctx $key]
	xcbcmac_update [list ctx $messages]
	set out [xcbcmac_done [list ctx]]

	return $out

}
