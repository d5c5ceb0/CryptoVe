#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# hash test case for TCL
#
# hash test
#
# Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
# functions:
# test_hash_md5
# test_hash_sha1
# test_hash_sha224
# test_hash_sha256
# test_hash_sha384
# test_hash_sha512
# test_hash_sm3
#===============================================================================
#

source [file join [file dirname [info script]] ../cryptove.tcl]


proc test_hash_md5 {} {
	set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
	set digest b3eb9ac023b813857b895dd3cc74ec11

	set d2 [md5_process $message]
	if {[cmp $d2 $digest]} {
		puts $d2
		puts $digest
		return -code error "md5_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 64
	md5_init md5_ctx
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		md5_update md5_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		md5_update md5_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [md5_done md5_ctx]
	if {[cmp $d3 $digest]} {
		puts $d3
		puts $digest
		return -code error "md5_{init update done} error!"
	}
	puts "md5 hash test successfully!"
}


proc test_hash_sha1 {} {
	set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
	set digest cae74849fc4ca9ae98ce22db01d0561beaa47bd6

	set d2 [sha1_process $message]
	if {[cmp $d2 $digest]} {
		puts $d2
		puts $digest
		return -code error "sha1_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 64
	sha1_init sha1_ctx
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sha1_update sha1_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sha1_update sha1_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sha1_done sha1_ctx]
	if {[cmp $d3 $digest]} {
		puts $d3
		puts $digest
		return -code error "sha1_{init update done} error!"
	}
	puts "sha1 hash test successfully!"
}


proc test_hash_sha224 {} {
	set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
	set digest 2234ac071a938111cb1cb79e054b548a80206cb38e0a038a565a3a05

	set d2 [sha224_process $message]
	if {[cmp $d2 $digest]} {
		puts $d2
		puts $digest
		return -code error "sha224_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 64
	sha224_init sha224_ctx
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sha224_update sha224_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sha224_update sha224_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sha224_done sha224_ctx]
	if {[cmp $d3 $digest]} {
		puts $d3
		puts $digest
		return -code error "sha224_{init update done} error!"
	}
	puts "sha224 hash test successfully!"
}

proc test_hash_sha256 {} {
	set message 6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839
	set digest af9f0cb3809944ba914dd2d28721c6f03956911f4450e481cb18ff9f92efdc65

	set d2 [sha256_process $message]
	if {[cmp $d2 $digest]} {
		puts $d2
		puts $digest
		return -code error "sha256_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 64
	sha256_init sha256_ctx
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sha256_update sha256_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sha256_update sha256_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sha256_done sha256_ctx]
	if {[cmp $d3 $digest]} {
		puts $d3
		puts $digest
		return -code error "sha256_{init update done} error!"
	}
	puts "sha256 hash test successfully!"
}


proc test_hash_sha384 {} {
	set message 4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c
	set digest d31114cf0abc09647b4737df418ea09d692054f0a10048a05d765e30398409597e4f6d1d83bff919f2584bd15a138430

	set d2 [sha384_process $message]
	if {[cmp $d2 $digest]} {
		puts $d2
		puts $digest
		return -code error "sha384_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 128
	sha384_init sha384_ctx
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sha384_update sha384_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sha384_update sha384_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sha384_done sha384_ctx]
	if {[cmp $d3 $digest]} {
		puts $d3
		puts $digest
		return -code error "sha384_{init update done} error!"
	}
	puts "sha384 hash test successfully!"
}


proc test_hash_sha512 {} {
	set message 4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536373839304142434445464748494a4b4c
	set digest 9bc1660a879982f04edee7fefab921f1e6e5fc7078023a0dd251987b6fcdbe9e7521a73e652b3e1ba4eb683d3967e39e37d21b057645b411b71efd461d3594fb

	set d2 [sha512_process $message]
	if {[cmp $d2 $digest]} {
		puts $d2
		puts $digest
		return -code error "sha512_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 128
	sha512_init sha512_ctx
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sha512_update sha512_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sha512_update sha512_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sha512_done sha512_ctx]
	if {[cmp $d3 $digest]} {
		puts $d3
		puts $digest
		return -code error "sha512_{init update done} error!"
	}
	puts "sha512 hash test successfully!"
}

proc test_hash_sm3 {} {
	set message 61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364
	set digest debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732

	set d2 [sm3_process $message]
	if {[cmp $d2 $digest]} {
		puts $d2
		puts $digest
		return -code error "sm3_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 128
	sm3_init sm3_ctx
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sm3_update sm3_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sm3_update sm3_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sm3_done sm3_ctx]
	if {[cmp $d3 $digest]} {
		puts $d3
		puts $digest
		return -code error "sm3_{init update done} error!"
	}
	puts "sm3 hash test successfully!"
}
