#===============================================================================
#chacha20 & poly1305  api for TCL
#
#chacha20 & poly1305 api
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#º¯Êý½éÉÜ
#1. chacha20_block
#2. poly1305_mac
#=============================================================================================

package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]



proc clamp_r {r} {
	set clampr [and $r 0ffffffc0ffffffc0ffffffc0fffffff]
}
proc poly1305_mac {mesg key} {
	set msglen [expr [string length $mesg]/2]
	set r [endian [string range $key 0 31]]
	set s [endian [string range $key 32 end]]
	puts ${r}_${s}
	set r [clamp_r $r]
	puts $r

	set a 00
	set p 03fffffffffffffffffffffffffffffffb
	for {set i 1} {$i <= [expr $msglen/16]} {incr i 1} {
		puts $i
		set n 01[endian [string range $mesg [expr ($i-1)*16*2] [expr $i*16*2-1]]]
		puts $n
		set a [add $a $n]
		puts $a
		set a [modmul $r $a $p]
		puts $a
	}
	if {$msglen%16} {
		set n 01[endian [string range $mesg [expr ($i-1)*16*2] end]]
		puts $n
		set a [add $a $n]
		puts $a
		set a [modmul $r $a $p]
		puts $a
	}
	set a [add $a $s]

	return [endian [string range $a 2 end]]
}

proc qround {sa sb sc sd} {
	upvar $sa a
	upvar $sb b
	upvar $sc c
	upvar $sd d

	set a [rem [add $a $b] 0100000000]
	set d [xor $a $d]
	set d [orr [rem [sft L $d 16] 0100000000] [rem [sft R $d 16] 0100000000]]
	set c [rem [add $c $d] 0100000000]
	set b [xor $b $c]
	set b [orr [rem [sft L $b 12] 0100000000] [rem [sft R $b 20] 0100000000]]
	set a [rem [add $a $b] 0100000000]
	set d [xor $d $a]
	set d [orr [rem [sft L $d  8] 0100000000] [rem [sft R $d 24] 0100000000]]
	set c [rem [add $c $d] 0100000000]
	set b [xor $b $c]
	set b [orr [rem [sft L $b  7] 0100000000] [rem [sft R $b 25] 0100000000]]
}

proc inner_block {state} {
	upvar $state i_state
	qround i_state(0) i_state(4) i_state(8)  i_state(12)
	qround i_state(1) i_state(5) i_state(9)  i_state(13)
	qround i_state(2) i_state(6) i_state(10) i_state(14)
	qround i_state(3) i_state(7) i_state(11) i_state(15)
	qround i_state(0) i_state(5) i_state(10) i_state(15)
	qround i_state(1) i_state(6) i_state(11) i_state(12)
	qround i_state(2) i_state(7) i_state(8)  i_state(13)
	qround i_state(3) i_state(4) i_state(9)  i_state(14)
}

proc chacha20_block {key counter nonce} {
	set constants {61707865 3320646e 79622d32 6b206574}
	set state(0) [lindex $constants 0]
	set state(1) [lindex $constants 1]
	set state(2) [lindex $constants 2]
	set state(3) [lindex $constants 3]
	for {set i 0} {$i < 8} {incr i 1} {
		set state([expr 4+$i]) [endian [string range $key [expr $i*8] [expr ($i+1)*8-1]]]
	}
	set state(12) $counter
	for {set i 0} {$i < 3} {incr i 1} {
		set state([expr 13+$i]) [endian [string range $nonce [expr $i*8] [expr ($i+1)*8-1]]]
	}
	for {set i 0} {$i < 16} {incr i} {
		set working_state($i) $state($i)
	}

	for {set i 0} {$i < 10} {incr i 1} {
		inner_block working_state
	}

	set out ""
	for {set i 0} {$i < 16} {incr i} {
		set state($i) [rem [add $working_state($i) $state($i)] 0100000000]
		append out [endian $state($i)]
	}

	return $out
}


