#===============================================================================
# hash test case for TCL
#
# hash test
#
# Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
# functions:
# test_hmac_md5
# test_hmac_sha1
# test_hmac_sha224
# test_hmac_sha256
# test_hmac_sha384
# test_hmac_sha512
# test_cmac
# test_cbcmac
# test_xcbcmac
#===============================================================================
#

source [file join [file dirname [info script]] ../cryptove.tcl]


proc test_hmac_md5 {} {
	set hkey 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
	set message 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
	set tag 3ba82db082e75093203ff41d9f4f6d52

	set d2 [md5_hmac_process $hkey $message]
	if {[cmp $d2 $tag]} {
		puts $d2
		puts $tag
		return -code error "md5_hmac_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 64
	md5_hmac_init md5_hmac_ctx $hkey
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		md5_hmac_update md5_hmac_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		md5_hmac_update md5_hmac_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [md5_hmac_done md5_hmac_ctx]
	if {[cmp $d3 $tag]} {
		puts $d3
		puts $tag
		return -code error "md5_hmac_{init update done} error!"
	}
	puts "md5 hmac api test successfully!"
}

proc test_hmac_sha1 {} {
	set hkey 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
	set message 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
	set tag 0d232f31b745171451e97fe73e9c307d9d5555bd

	set d2 [sha1_hmac_process $hkey $message]
	if {[cmp $d2 $tag]} {
		puts $d2
		puts $tag
		return -code error "sha1_hmac_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 64
	sha1_hmac_init sha1_hmac_ctx $hkey
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sha1_hmac_update sha1_hmac_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sha1_hmac_update sha1_hmac_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sha1_hmac_done sha1_hmac_ctx]
	if {[cmp $d3 $tag]} {
		puts $d3
		puts $tag
		return -code error "sha1_hmac_{init update done} error!"
	}
	puts "sha1 hmac api test successfully!"
}

proc test_hmac_sha224 {} {
	set hkey 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
	set message 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
	set tag 13e71b85772ec123d2614870072c2330f70bd2c8f7973d27b032825b

	set d2 [sha224_hmac_process $hkey $message]
	if {[cmp $d2 $tag]} {
		puts $d2
		puts $tag
		return -code error "sha224_hmac_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 64
	sha224_hmac_init sha224_hmac_ctx $hkey
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sha224_hmac_update sha224_hmac_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sha224_hmac_update sha224_hmac_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sha224_hmac_done sha224_hmac_ctx]
	if {[cmp $d3 $tag]} {
		puts $d3
		puts $tag
		return -code error "sha224_hmac_{init update done} error!"
	}
	puts "sha224 hmac api test successfully!"
}

proc test_hmac_sha256 {} {
	set hkey 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
	set message 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
	set tag 3c0b856e96f74d7f74d1f8e8838456dadcfc85dc34403c7f0ddc168108c2ce13

	set d2 [sha256_hmac_process $hkey $message]
	if {[cmp $d2 $tag]} {
		puts $d2
		puts $tag
		return -code error "sha256_hmac_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 64
	sha256_hmac_init sha256_hmac_ctx $hkey
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sha256_hmac_update sha256_hmac_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sha256_hmac_update sha256_hmac_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sha256_hmac_done sha256_hmac_ctx]
	if {[cmp $d3 $tag]} {
		puts $d3
		puts $tag
		return -code error "sha256_hmac_{init update done} error!"
	}
	puts "sha256 hmac api test successfully!"
}

proc test_hmac_sha384 {} {
	set hkey 41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
	set message 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
	set tag e685fa4ea7efd11b2d583cd7f035fded03612316083df1e6659266d5514a0b7a9f4e9af505c567501e1a8bbca16435f9

	set d2 [sha384_hmac_process $hkey $message]
	if {[cmp $d2 $tag]} {
		puts $d2
		puts $tag
		return -code error "sha384_hmac_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 64
	sha384_hmac_init sha384_hmac_ctx $hkey
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sha384_hmac_update sha384_hmac_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sha384_hmac_update sha384_hmac_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sha384_hmac_done sha384_hmac_ctx]
	if {[cmp $d3 $tag]} {
		puts $d3
		puts $tag
		return -code error "sha384_hmac_{init update done} error!"
	}
	puts "sha384 hmac api test successfully!"
}


proc test_hmac_sha512 {} {
	set hkey 41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141
	set message 54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461
	set tag 24e74026d857f6f4b9ac8e645f0753755e4895235e71a7833ff2c7c29b2cd3c9b3494b02fea0e43a91a3a8cd1970734d4172f058309f099331929153facebff8
	set d2 [sha512_hmac_process $hkey $message]
	if {[cmp $d2 $tag]} {
		puts $d2
		puts $tag
		return -code error "sha512_hmac_process error!"
	}
	
	set mlen [expr [string length $message]/2]
	set block_len 64
	sha512_hmac_init sha512_hmac_ctx $hkey
	for {set i 0} {$i < $mlen/$block_len} {incr i 1} {
		sha512_hmac_update sha512_hmac_ctx [string range $message [expr $block_len*$i*2] [expr ($i+1)*$block_len*2-1]]
	}
	if {$mlen%$block_len} {
		sha512_hmac_update sha512_hmac_ctx [string range $message [expr $block_len*$i*2] end]
	}
	set d3 [sha512_hmac_done sha512_hmac_ctx]
	if {[cmp $d3 $tag]} {
		puts $d3
		puts $tag
		return -code error "sha512_hmac_{init update done} error!"
	}
	puts "sha512 hmac api test successfully!"
}

proc test_cmac {} {
	set key 2b7e151628aed2a6abf7158809cf4f3c
	set m   6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411
	set s   dfa66747de9ae63030ca32611497c827
	set s1 [aes_cmac_process $key $m]
	if {[cmp $s1 $s]} {
		puts $s1
		puts $s
		return -code error "aes_cmac_process  error!"
	}
	puts "aes_cmac_process test successfully!"

}

proc test_cbcmac {} {
	set key 2b7e151628aed2a6abf7158809cf4f3c
	set m   6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set s   a7356e1207bb406639e5e5ceb9a9ed93

	set s1 [aes_cbcmac_process $key $m]
	if {[cmp $s1 $s]} {
		puts $s1
		puts $s
		return -code error "aes_cbcmac_process  error!"
	}
	puts "aes_cbcmac_process test successfully!"
}

proc test_xcbcmac {} {
	set key 000102030405060708090a0b0c0d0e0f
	set m   000102
	set s   5b376580ae2f19afe7219ceef172756f

	set s1 [aes_xcbcmac_process $key $m]
	if {[cmp $s1 $s]} {
		puts $s1
		puts $s
		return -code error "aes_xcbcmac_process  error!"
	}
	puts "aes_xcbcmac_process test successfully!"
}

