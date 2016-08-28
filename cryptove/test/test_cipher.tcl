#===============================================================================
# cipher test case for TCL
#
# cipher test
#
# Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
# functions:
# test_aes_ecb 
# test_aes_cbc
# test_aes_cfb
# test_aes_ofb
# test_aes_ctr
# test_aes_xts
# test_des_ecb 
# test_des_cbc
# test_des3_ecb 
# test_des3_cbc
# test_sm4_ecb 
# test_sm4_cbc
#===============================================================================
#

source [file join [file dirname [info script]] ../cryptove.tcl]

proc test_aes_ecb {} {
	set k(128) 2b7e151628aed2a6abf7158809cf4f3c
	set m(128) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(128) 3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4
	set k(192) 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
	set m(192) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(192) bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e
	set k(256) 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
	set m(256) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(256) f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7

	foreach klen {128 192 256} {
		set c1 [aes_ecb_process enc $k($klen) $m($klen)]
		if {[cmp $c1 $c($klen)]} {
			puts $c1
			puts $c($klen)
			return -code error "aes_ecb_process  keylen=$klen encrypt error!"
		}
		set m1 [aes_ecb_process dec $k($klen) $c($klen)]
		if {[cmp $m1 $m($klen)]} {
			puts $m1
			puts $m($klen)
			return -code error "aes_ecb_process keylen=$klen decrypt error!"
		}
		puts "aes_ecb_process keylen=$klen pass for std data."
	}

	set block_len 16

	foreach klen {128 192 256} {
		for {set i $block_len} {$i <= 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set m2 [rand $i 0 256]
			set c1 [aes_ecb_process enc $k2 $m2]
			set m1 [aes_ecb_process dec $k2 $c1]
			if {[cmp $m2 $m1]} {
				puts $m1
				puts $m2
				return -code error "aes_ecb_process keylen=$klen tests error"
			}

		}
		puts "aes_ecb_process keylen=$klen pass!"
	}

	foreach klen {128 192 256} {
		for {set i $block_len} {$i < 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set m2 [rand $i 0 256]
			set c1 ""
			aes_ecb_init ecb_ctx enc $k2
			for {set j 0} {$j < $i} {incr j $block_len} {
				append c1 [aes_ecb_update ecb_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
			}
			aes_ecb_done ecb_ctx

			aes_ecb_init ecb_ctx dec $k2
			set m1 [aes_ecb_update ecb_ctx $c1]
			aes_ecb_done ecb_ctx
			if {[cmp $m1 $m2]} {
				puts $m1
				puts $m2
			  return -code error "aes_ecb_{init update done} keylen=$klen error"
			}
		}
		puts "aes_ecb_{init update done} keylen=$klen pass!"
	}

}


proc test_aes_cbc {} {
	set k(128) 2b7e151628aed2a6abf7158809cf4f3c
	set iv(128) 000102030405060708090a0b0c0d0e0f
	set m(128) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(128) 7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7
	set k(192) 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
	set iv(192) 000102030405060708090a0b0c0d0e0f
	set m(192) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(192) 4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd
	set k(256) 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
	set iv(256) 000102030405060708090a0b0c0d0e0f
	set m(256) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(256) f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b

	foreach klen {128 192 256} {
		set c1 [aes_cbc_process enc $k($klen) $iv($klen) $m($klen)]
		if {[cmp $c1 $c($klen)]} {
			puts $c1
			puts $c($klen)
			return -code error "aes_cbc_process  keylen=$klen encrypt error!"
		}
		set m1 [aes_cbc_process dec $k($klen) $iv($klen) $c($klen)]
		if {[cmp $m1 $m($klen)]} {
			puts $m1
			puts $m($klen)
			return -code error "aes_cbc_process keylen=$klen decrypt error!"
		}
		puts "aes_cbc_process keylen=$klen pass for std data."
	}

	set block_len 16

	foreach klen {128 192 256} {
		for {set i $block_len} {$i <= 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 [aes_cbc_process enc $k2 $iv2 $m2]
			set m1 [aes_cbc_process dec $k2 $iv2 $c1]
			if {[cmp $m2 $m1]} {
				puts $m1
				puts $m2
				return -code error "aes_cbc_process keylen=$klen tests error"
			}

		}
		puts "aes_cbc_process keylen=$klen pass!"
	}

	foreach klen {128 192 256} {
		for {set i $block_len} {$i < 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 ""
			aes_cbc_init cbc_ctx enc $k2 $iv2
			for {set j 0} {$j < $i} {incr j $block_len} {
				append c1 [aes_cbc_update cbc_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
			}
			aes_cbc_done cbc_ctx

			aes_cbc_init cbc_ctx dec $k2 $iv2
			set m1 [aes_cbc_update cbc_ctx $c1]
			aes_cbc_done cbc_ctx
			if {[cmp $m1 $m2]} {
				puts $m1
				puts $m2
			  return -code error "aes_cbc_{init update done} keylen=$klen error"
			}
		}
		puts "aes_cbc_{init update done} keylen=$klen pass!"
	}

}


proc test_aes_cfb {} {
	set k(128) 2b7e151628aed2a6abf7158809cf4f3c
	set iv(128) 000102030405060708090a0b0c0d0e0f
	set m(128) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(128) 3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6
	set k(192) 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
	set iv(192) 000102030405060708090a0b0c0d0e0f
	set m(192) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(192) cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff
	set k(256) 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
	set iv(256) 000102030405060708090a0b0c0d0e0f
	set m(256) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(256) dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471

	foreach klen {128 192 256} {
		set c1 [aes_cfb_process enc $k($klen) $iv($klen) $m($klen)]
		if {[cmp $c1 $c($klen)]} {
			puts $c1
			puts $c($klen)
			return -code error "aes_cfb_process  keylen=$klen encrypt error!"
		}
		set m1 [aes_cfb_process dec $k($klen) $iv($klen) $c($klen)]
		if {[cmp $m1 $m($klen)]} {
			puts $m1
			puts $m($klen)
			return -code error "aes_cfb_process keylen=$klen decrypt error!"
		}
		puts "aes_cfb_process keylen=$klen pass for std data."
	}

	set block_len 16

	foreach klen {128 192 256} {
		for {set i $block_len} {$i <= 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 [aes_cfb_process enc $k2 $iv2 $m2]
			set m1 [aes_cfb_process dec $k2 $iv2 $c1]
			if {[cmp $m2 $m1]} {
				puts $m1
				puts $m2
				return -code error "aes_cfb_process keylen=$klen tests error"
			}

		}
		puts "aes_cfb_process keylen=$klen pass!"
	}

	foreach klen {128 192 256} {
		for {set i $block_len} {$i < 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 ""
			aes_cfb_init cfb_ctx enc $k2 $iv2
			for {set j 0} {$j < $i} {incr j $block_len} {
				append c1 [aes_cfb_update cfb_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
			}
			aes_cfb_done cfb_ctx

			aes_cfb_init cfb_ctx dec $k2 $iv2
			set m1 [aes_cfb_update cfb_ctx $c1]
			aes_cfb_done cfb_ctx
			if {[cmp $m1 $m2]} {
				puts $m1
				puts $m2
			  return -code error "aes_cfb_{init update done} keylen=$klen error"
			}
		}
		puts "aes_cfb_{init update done} keylen=$klen pass!"
	}

}


proc test_aes_ofb {} {
	set k(128) 2b7e151628aed2a6abf7158809cf4f3c
	set iv(128) 000102030405060708090a0b0c0d0e0f
	set m(128) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(128) 3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e
	set k(192) 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
	set iv(192) 000102030405060708090a0b0c0d0e0f
	set m(192) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(192) cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a
	set k(256) 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
	set iv(256) 000102030405060708090a0b0c0d0e0f
	set m(256) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(256) dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484

	foreach klen {128 192 256} {
		set c1 [aes_ofb_process enc $k($klen) $iv($klen) $m($klen)]
		if {[cmp $c1 $c($klen)]} {
			puts $c1
			puts $c($klen)
			return -code error "aes_ofb_process keylen=$klen encrypt error!"
		}
		set m1 [aes_ofb_process dec $k($klen) $iv($klen) $c($klen)]
		if {[cmp $m1 $m($klen)]} {
			puts $m1
			puts $m($klen)
			return -code error "aes_ofb_process keylen=$klen decrypt error!"
		}
		puts "aes_ofb_process keylen=$klen pass for std data."
	}

	set block_len 16

	foreach klen {128 192 256} {
		for {set i $block_len} {$i <= 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 [aes_ofb_process enc $k2 $iv2 $m2]
			set m1 [aes_ofb_process dec $k2 $iv2 $c1]
			if {[cmp $m2 $m1]} {
				puts $m1
				puts $m2
				return -code error "aes_ofb_process keylen=$klen tests error"
			}

		}
		puts "aes_ofb_process keylen=$klen pass!"
	}

	foreach klen {128 192 256} {
		for {set i $block_len} {$i < 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 ""
			aes_ofb_init ofb_ctx enc $k2 $iv2
			for {set j 0} {$j < $i} {incr j $block_len} {
				append c1 [aes_ofb_update ofb_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
			}
			aes_ofb_done ofb_ctx

			aes_ofb_init ofb_ctx dec $k2 $iv2
			set m1 [aes_ofb_update ofb_ctx $c1]
			aes_ofb_done ofb_ctx
			if {[cmp $m1 $m2]} {
				puts $m1
				puts $m2
			  return -code error "aes_ofb_{init update done} keylen=$klen error"
			}
		}
		puts "aes_ofb_{init update done} keylen=$klen pass!"
	}

}

proc test_aes_ctr {} {
	set k(128) 2b7e151628aed2a6abf7158809cf4f3c
	set iv(128) f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
	set m(128) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(128) 874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee
	set k(192) 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
	set iv(192) f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
	set m(192) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(192) 1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050
	set k(256) 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
	set iv(256) f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
	set m(256) 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
	set c(256) 601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6

	foreach klen {128 192 256} {
		set c1 [aes_ctr_process enc $k($klen) $iv($klen) $m($klen)]
		if {[cmp $c1 $c($klen)]} {
			puts $c1
			puts $c($klen)
			return -code error "aes_ctr_process keylen=$klen encrypt error!"
		}
		set m1 [aes_ctr_process dec $k($klen) $iv($klen) $c($klen)]
		if {[cmp $m1 $m($klen)]} {
			puts $m1
			puts $m($klen)
			return -code error "aes_ctr_process keylen=$klen decrypt error!"
		}
		puts "aes_ctr_process keylen=$klen pass for std data."
	}

	set block_len 16

	foreach klen {128 192 256} {
		for {set i $block_len} {$i <= 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 [aes_ctr_process enc $k2 $iv2 $m2]
			set m1 [aes_ctr_process dec $k2 $iv2 $c1]
			if {[cmp $m2 $m1]} {
				puts $m1
				puts $m2
				return -code error "aes_ctr_process keylen=$klen tests error"
			}

		}
		puts "aes_ctr_process keylen=$klen pass!"
	}

	foreach klen {128 192 256} {
		for {set i $block_len} {$i < 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 ""
			aes_ctr_init ctr_ctx enc $k2 $iv2
			for {set j 0} {$j < $i} {incr j $block_len} {
				append c1 [aes_ctr_update ctr_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
			}
			aes_ctr_done ctr_ctx

			aes_ctr_init ctr_ctx dec $k2 $iv2
			set m1 [aes_ctr_update ctr_ctx $c1]
			aes_ctr_done ctr_ctx
			if {[cmp $m1 $m2]} {
				puts $m1
				puts $m2
			  return -code error "aes_ctr_{init update done} keylen=$klen error"
			}
		}
		puts "aes_ctr_{init update done} keylen=$klen pass!"
	}

}


proc test_aes_xts {} {
	set k(128) fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222 
	set iv(128) 33333333330000000000000000000000
	set m(128) 4444444444444444444444444444444444444444444444444444444444444444
	set c(128) af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89
	set k(256) 27182818284590452353602874713526624977572470936999595749669676273141592653589793238462643383279502884197169399375105820974944592
	set iv(256) ff000000000000000000000000000000
	set m(256) 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
	set c(256) 1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a
	set k(nalign) fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0
	set iv(nalign) 9a785634120000000000000000000000
	set m(nalign) 000102030405060708090a0b0c0d0e0f101112
	set c(nalign) e5df1351c0544ba1350b3363cd8ef4beedbf9d

	foreach klen {128 256 nalign} {
		set c1 [aes_xts_process enc $k($klen) $iv($klen) $m($klen)]
		if {[cmp $c1 $c($klen)]} {
			puts $c1
			puts $c($klen)
			return -code error "aes_xts_process keylen=$klen encrypt error!"
		}
		set m1 [aes_xts_process dec $k($klen) $iv($klen) $c($klen)]
		if {[cmp $m1 $m($klen)]} {
			puts $m1
			puts $m($klen)
			return -code error "aes_xts_process keylen=$klen decrypt error!"
		}
		puts "aes_xts_process keylen=$klen pass for std data."
	}

	set block_len 16

	foreach klen {128 256} {
		for {set i $block_len} {$i <= 1024} {incr i 1} {
			set k2 [rand [expr $klen/8 * 2] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 [aes_xts_process enc $k2 $iv2 $m2]
			set m1 [aes_xts_process dec $k2 $iv2 $c1]
			if {[cmp $m2 $m1]} {
				puts $m1
				puts $m2
				return -code error "aes_xts_process keylen=$klen tests error"
			}
		}
		puts "aes_xts_process keylen=$klen pass!"
	}

	foreach klen {128 256} {
		for {set i $block_len} {$i < 1024} {incr i 1} {
			set k2 [rand [expr $klen/8 * 2] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 ""
			aes_xts_init xts_ctx enc $k2 $iv2
			for {set j 0} {$j < [expr ($i/$block_len-1)*$block_len]} {incr j $block_len} {
				append c1 [aes_xts_update xts_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
			}
			append c1 [aes_xts_update xts_ctx [string range $m2 [expr $j * 2] end]]
			aes_xts_done xts_ctx

			aes_xts_init xts_ctx dec $k2 $iv2
			set m1 [aes_xts_update xts_ctx $c1]
			aes_xts_done xts_ctx
			if {[cmp $m1 $m2]} {
				puts $m1
				puts $m2
			  return -code error "aes_xts_{init update done} keylen=$klen error"
			}
		}
		puts "aes_xts_{init update done} keylen=$klen pass!"
	}


}

proc test_des_ecb {} {
	#set k
	#set m
	#set c

	#set c1 [des_ecb_process enc $k $m]
	#if {[cmp $c1 $c]} {
	#	puts $c1
	#	puts $c
	#	return -code error "des_ecb_process encrypt error!"
	#}
	#set m1 [des_ecb_process dec $k $c]
	#if {[cmp $m1 $m]} {
	#	puts $m1
	#	puts $m
	#	return -code error "des_ecb_process decrypt error!"
	#}
	#puts "des_ecb_process pass for std data."

	set block_len 8

	for {set i $block_len} {$i <= 1024} {incr i $block_len} {
		set k2 [rand 8 0 256]
		set m2 [rand $i 0 256]
		set c1 [des_ecb_process enc $k2 $m2]
		set m1 [des_ecb_process dec $k2 $c1]
		if {[cmp $m2 $m1]} {
			puts $m1
			puts $m2
			return -code error "des_ecb_process tests error"
		}

	}
	puts "des_ecb_process pass!"

	for {set i $block_len} {$i < 1024} {incr i $block_len} {
		set k2 [rand 8 0 256]
		set m2 [rand $i 0 256]
		set c1 ""
		des_ecb_init ecb_ctx enc $k2
		for {set j 0} {$j < $i} {incr j $block_len} {
			append c1 [des_ecb_update ecb_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
		}
		des_ecb_done ecb_ctx

		des_ecb_init ecb_ctx dec $k2
		set m1 [des_ecb_update ecb_ctx $c1]
		des_ecb_done ecb_ctx
		if {[cmp $m1 $m2]} {
			puts $m1
			puts $m2
		  return -code error "des_ecb_{init update done} error"
		}
	}
	puts "des_ecb_{init update done} pass!"

}


proc test_des_cbc {} {
	#set k
	#set iv
	#set m
	#set c

	#set c1 [des_cbc_process enc $k $iv $m]
	#if {[cmp $c1 $c]} {
	#	puts $c1
	#	puts $c
	#	return -code error "des_cbc_process encrypt error!"
	#}
	#set m1 [des_cbc_process dec $k $iv $c]
	#if {[cmp $m1 $m]} {
	#	puts $m1
	#	puts $m
	#	return -code error "des_cbc_process decrypt error!"
	#}
	#puts "des_cbc_process pass for std data."

	set block_len 8

	for {set i $block_len} {$i <= 1024} {incr i $block_len} {
		set k2 [rand 8 0 256]
		set iv2 [rand $block_len 0 256]
		set m2 [rand $i 0 256]
		set c1 [des_cbc_process enc $k2 $iv2 $m2]
		set m1 [des_cbc_process dec $k2 $iv2 $c1]
		if {[cmp $m2 $m1]} {
			puts $m1
			puts $m2
			return -code error "des_cbc_process tests error"
		}

	}
	puts "des_cbc_process pass!"

	for {set i $block_len} {$i < 1024} {incr i $block_len} {
		set k2 [rand 8 0 256]
		set iv2 [rand $block_len 0 256]
		set m2 [rand $i 0 256]
		set c1 ""
		des_cbc_init cbc_ctx enc $k2 $iv2
		for {set j 0} {$j < $i} {incr j $block_len} {
			append c1 [des_cbc_update cbc_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
		}
		des_cbc_done cbc_ctx

		des_cbc_init cbc_ctx dec $k2 $iv2
		set m1 [des_cbc_update cbc_ctx $c1]
		des_cbc_done cbc_ctx
		if {[cmp $m1 $m2]} {
			puts $m1
			puts $m2
		  return -code error "des_cbc_{init update done} error"
		}
	}
	puts "des_cbc_{init update done} pass!"

}

proc test_des3_ecb {} {
	#set k(128) 
	#set m(128) 
	#set c(128) 
	#set k(192) 
	#set m(192) 
	#set c(192) 

	#foreach klen {128 192} {
	#	set c1 [des3_ecb_process enc $k($klen) $m($klen)]
	#	if {[cmp $c1 $c($klen)]} {
	#		puts $c1
	#		puts $c($klen)
	#		return -code error "des3_ecb_process  keylen=$klen encrypt error!"
	#	}
	#	set m1 [des3_ecb_process dec $k($klen) $c($klen)]
	#	if {[cmp $m1 $m($klen)]} {
	#		puts $m1
	#		puts $m($klen)
	#		return -code error "des3_ecb_process keylen=$klen decrypt error!"
	#	}
	#	puts "des3_ecb_process keylen=$klen pass for std data."
	#}

	set block_len 8

	foreach klen {128 192} {
		for {set i $block_len} {$i <= 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set m2 [rand $i 0 256]
			set c1 [des3_ecb_process enc $k2 $m2]
			set m1 [des3_ecb_process dec $k2 $c1]
			if {[cmp $m2 $m1]} {
				puts $m1
				puts $m2
				return -code error "des3_ecb_process keylen=$klen tests error"
			}

		}
		puts "des3_ecb_process keylen=$klen pass!"
	}

	foreach klen {128 192} {
		for {set i $block_len} {$i < 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set m2 [rand $i 0 256]
			set c1 ""
			des3_ecb_init ecb_ctx enc $k2
			for {set j 0} {$j < $i} {incr j $block_len} {
				append c1 [des3_ecb_update ecb_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
			}
			des3_ecb_done ecb_ctx

			des3_ecb_init ecb_ctx dec $k2
			set m1 [des3_ecb_update ecb_ctx $c1]
			des3_ecb_done ecb_ctx
			if {[cmp $m1 $m2]} {
				puts $m1
				puts $m2
			  return -code error "des3_ecb_{init update done} keylen=$klen error"
			}
		}
		puts "des3_ecb_{init update done} keylen=$klen pass!"
	}

}


proc test_des3_cbc {} {
	#set k(128) 
	#set iv(128)
	#set m(128) 
	#set c(128) 
	#set k(192) 
	#set iv(192)
	#set m(192) 
	#set c(192) 

	#foreach klen {128 192} {
	#	set c1 [des3_cbc_process enc $k($klen) $iv($klen) $m($klen)]
	#	if {[cmp $c1 $c($klen)]} {
	#		puts $c1
	#		puts $c($klen)
	#		return -code error "des3_cbc_process  keylen=$klen encrypt error!"
	#	}
	#	set m1 [des3_cbc_process dec $k($klen) $iv($klen) $c($klen)]
	#	if {[cmp $m1 $m($klen)]} {
	#		puts $m1
	#		puts $m($klen)
	#		return -code error "des3_cbc_process keylen=$klen decrypt error!"
	#	}
	#	puts "des3_cbc_process keylen=$klen pass for std data."
	#}

	set block_len 8

	foreach klen {128 192} {
		for {set i $block_len} {$i <= 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 [des3_cbc_process enc $k2 $iv2 $m2]
			set m1 [des3_cbc_process dec $k2 $iv2 $c1]
			if {[cmp $m2 $m1]} {
				puts $m1
				puts $m2
				return -code error "des3_cbc_process keylen=$klen tests error"
			}

		}
		puts "des3_cbc_process keylen=$klen pass!"
	}

	foreach klen {128 192} {
		for {set i $block_len} {$i < 1024} {incr i $block_len} {
			set k2 [rand [expr $klen/8] 0 256]
			set iv2 [rand $block_len 0 256]
			set m2 [rand $i 0 256]
			set c1 ""
			des3_cbc_init cbc_ctx enc $k2 $iv2
			for {set j 0} {$j < $i} {incr j $block_len} {
				append c1 [des3_cbc_update cbc_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
			}
			des3_cbc_done cbc_ctx

			des3_cbc_init cbc_ctx dec $k2 $iv2
			set m1 [des3_cbc_update cbc_ctx $c1]
			des3_cbc_done cbc_ctx
			if {[cmp $m1 $m2]} {
				puts $m1
				puts $m2
			  return -code error "des3_cbc_{init update done} keylen=$klen error"
			}
		}
		puts "des3_cbc_{init update done} keylen=$klen pass!"
	}

}

proc test_sm4_ecb {} {
	#set k
	#set m
	#set c

	#set c1 [sm4_ecb_process enc $k $m]
	#if {[cmp $c1 $c]} {
	#	puts $c1
	#	puts $c
	#	return -code error "sm4_ecb_process encrypt error!"
	#}
	#set m1 [sm4_ecb_process dec $k $c]
	#if {[cmp $m1 $m]} {
	#	puts $m1
	#	puts $m
	#	return -code error "sm4_ecb_process decrypt error!"
	#}
	#puts "sm4_ecb_process pass for std data."

	set block_len 16

	for {set i $block_len} {$i <= 1024} {incr i $block_len} {
		set k2 [rand 16 0 256]
		set m2 [rand $i 0 256]
		set c1 [sm4_ecb_process enc $k2 $m2]
		set m1 [sm4_ecb_process dec $k2 $c1]
		if {[cmp $m2 $m1]} {
			puts $m1
			puts $m2
			return -code error "sm4_ecb_process tests error"
		}

	}
	puts "sm4_ecb_process pass!"

	for {set i $block_len} {$i < 1024} {incr i $block_len} {
		set k2 [rand 16 0 256]
		set m2 [rand $i 0 256]
		set c1 ""
		sm4_ecb_init ecb_ctx enc $k2
		for {set j 0} {$j < $i} {incr j $block_len} {
			append c1 [sm4_ecb_update ecb_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
		}
		sm4_ecb_done ecb_ctx

		sm4_ecb_init ecb_ctx dec $k2
		set m1 [sm4_ecb_update ecb_ctx $c1]
		sm4_ecb_done ecb_ctx
		if {[cmp $m1 $m2]} {
			puts $m1
			puts $m2
		  return -code error "sm4_ecb_{init update done} error"
		}
	}
	puts "sm4_ecb_{init update done} pass!"

}


proc test_sm4_cbc {} {
	#set k
	#set iv
	#set m
	#set c

	#set c1 [sm4_cbc_process enc $k $iv $m]
	#if {[cmp $c1 $c]} {
	#	puts $c1
	#	puts $c
	#	return -code error "sm4_cbc_process encrypt error!"
	#}
	#set m1 [sm4_cbc_process dec $k $iv $c]
	#if {[cmp $m1 $m]} {
	#	puts $m1
	#	puts $m
	#	return -code error "sm4_cbc_process decrypt error!"
	#}
	#puts "sm4_cbc_process pass for std data."

	set block_len 16

	for {set i $block_len} {$i <= 1024} {incr i $block_len} {
		set k2 [rand 16 0 256]
		set iv2 [rand $block_len 0 256]
		set m2 [rand $i 0 256]
		set c1 [sm4_cbc_process enc $k2 $iv2 $m2]
		set m1 [sm4_cbc_process dec $k2 $iv2 $c1]
		if {[cmp $m2 $m1]} {
			puts $m1
			puts $m2
			return -code error "sm4_cbc_process tests error"
		}

	}
	puts "sm4_cbc_process pass!"

	for {set i $block_len} {$i < 1024} {incr i $block_len} {
		set k2 [rand 16 0 256]
		set iv2 [rand $block_len 0 256]
		set m2 [rand $i 0 256]
		set c1 ""
		sm4_cbc_init cbc_ctx enc $k2 $iv2
		for {set j 0} {$j < $i} {incr j $block_len} {
			append c1 [sm4_cbc_update cbc_ctx [string range $m2 [expr $j * 2] [expr ($j + $block_len)*2 - 1]]]
		}
		sm4_cbc_done cbc_ctx

		sm4_cbc_init cbc_ctx dec $k2 $iv2
		set m1 [sm4_cbc_update cbc_ctx $c1]
		sm4_cbc_done cbc_ctx
		if {[cmp $m1 $m2]} {
			puts $m1
			puts $m2
		  return -code error "sm4_cbc_{init update done} error"
		}
	}
	puts "sm4_cbc_{init update done} pass!"

}

