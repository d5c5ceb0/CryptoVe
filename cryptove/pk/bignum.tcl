#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#bignum for Tcl
#
#Wei Zhang <d5c5ceb0@gmail.com>   2019.05.07
#
#===============================================================================
# to_mont_domain : convert from montgomery domain
# from_mont_domain : convert to montgomery domain
# modadd_mont : modadd in montgomery domain
# modsub_mont : modsub in montgomery domain
# modinv_mont : modin in montgomery domain
# modmul_mont : modmul in montgomery domain
# a2j : affine to jacobian
# j2a : jacobian to affine
# a2j_mont: affine to jacobian in montgomery domain
# j2a_mont: jacobian to affine in montgomery domain
# pdbl_j_mont : point double in montgomery domain in montgomery domain
# padd_j_mont : point add in montgomery domain in jacobian coordinates
#===============================================================================


package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]

# x*r mod p
proc to_mont_domain {x ecc_p modsize} {
    set r [modexp 02 [dec2hex $modsize] $ecc_p]
	return  [modmul $x $r $ecc_p]
}

# x*(r^-1) mod p
proc from_mont_domain {x ecc_p modsize} {
	set r [modexp 02 [dec2hex $modsize] $ecc_p]
	set rinv [modinv $r $ecc_p]
	return  [modmul $x $rinv $ecc_p]
}

proc modadd_mont {x y ecc_p} {
	return [modadd $x $y $ecc_p]
}

proc modsub_mont {x y ecc_p} {
	return [modsub $x $y $ecc_p]
}

proc modinv_mont {x ecc_p modsize} {
	set r [modexp 02 [dec2hex $modsize] $ecc_p]
	set rinv [modinv $r $ecc_p]

	set x1 [modmul $rinv $x $ecc_p]
	set xinv [modinv $x1 $ecc_p]
	return [modmul $r $xinv $ecc_p]
}

proc modmul_mont {x y ecc_p modsize} {
	set r [modexp 02 [dec2hex $modsize] $ecc_p]
	set rinv [modinv $r $ecc_p]

	set xy [modmul $x $y $ecc_p]
	return [modmul $xy $rinv $ecc_p]
}

proc a2j {x y} {
	return [list $x $y 1]
}

proc j2a {x y z $ecc_p} {
    set r 01

	set zinv [modinv $z $ecc_p]
	set zinv2 [modmul $zinv $zinv $ecc_p]
	set zinv3 [modmul $zinv2 $zinv $ecc_p]

	set x1 [modmul $zinv2 $x $ecc_p]
	set y1 [modmul $zinv3 $y $ecc_p]

	return [list $x1 $y1 $r]
}


proc a2j_mont {x y ecc_p modsize} {
	set r [modexp 02 [dec2hex $modsize] $ecc_p]
	return [list $x $y $r]
}

proc j2a_mont {x y z ecc_p modsize} {
	set r [modexp 02 [dec2hex $modsize] $ecc_p]

	set zinv [modinv_mont $z $ecc_p $modsize]
	set zinv2 [modmul_mont $zinv $zinv $ecc_p $modsize]
	set zinv3 [modmul_mont  $zinv2 $zinv $ecc_p $modsize]

	set x1 [modmul_mont $zinv2 $x $ecc_p $modsize]
	set y1 [modmul_mont $zinv3 $y $ecc_p $modsize]

	return [list $x1 $y1 $r]
}

proc pdbl_j_mont {x y z ecc_p ecc_a modsize} {

	set y2 [modmul_mont $y $y $ecc_p $modsize]
	set y4 [modmul_mont $y2 $y2 $ecc_p $modsize]
	set s  [modmul_mont [modmul_mont [to_mont_domain 04] $x $ecc_p $modsize] $y2 $ecc_p $modsize]

	set x2 [modmul_mont $x $x $ecc_p $modsize]
	set x2_3 [modmul_mont [to_mont_domain 03 $ecc_p $modsize] $x2 $ecc_p $modsize]
	set z2 [modmul_mont $z $z $ecc_p $modsize]
	set z4 [modmul_mont $z2 $z2 $ecc_p $modsize]
	set z4_a [modmul_mont [to_mont_domain $ecc_a $ecc_p $modsize] $z4 $ecc_p $modsize]
	set m [modadd_mont $x2_3 $z4_a $ecc_p]

	set x1 [modsub_mont [modmul_mont $m $m $ecc_p $modsize] [modmul_mont [to_mont_domain 02 $ecc_p $modsize] $s $ecc_p $modsize] $ecc_p]
	set y1 [modsub_mont [modmul_mont $m [modsub_mont $s $x1 $ecc_p] $ecc_p $modsize] [modmul_mont [to_mont_domain 08 $ecc_p $modsize] $y4 $ecc_p $modsize] $ecc_p]
	set z1 [modmul_mont [to_mont_domain 02 $ecc_p $modsize] [modmul_mont $y $z $ecc_p $modsize] $ecc_p $modsize]

	#j2a_mont $x1 $y1 $z1
	return [list $x1 $y1 $z1]
}

proc padd_j_mont {x1 y1 z1 x2 y2 z2 ecc_p ecc_a modsize} {
	set z2_2 [modmul_mont $z2 $z2 $ecc_p $modsize]
	set u1   [modmul_mont $x1 $z2_2 $ecc_p $modsize]

	set z1_2 [modmul_mont $z1 $z1 $ecc_p $modsize]
	set u2   [modmul_mont $x2 $z1_2 $ecc_p $modsize]

	set z2_3 [modmul_mont $z2_2 $z2 $ecc_p $modsize]
	set s1   [modmul_mont $y1 $z2_3 $ecc_p $modsize]

	set z1_3 [modmul_mont $z1_2 $z1 $ecc_p $modsize]
	set s2   [modmul_mont $y2 $z1_3 $ecc_p $modsize]

	if {![cmp $u1 $u2]} {
		if {[cmp $s1 $s2]} {
			puts "infinity point"
			return [list 0 0 0]
		} else {
			return [pdbl_j_mont $x1 $y1 $z1 $ecc_p $ecc_a $modsize]
		}
	}
	set h    [modsub_mont $u2 $u1 $ecc_p]
	set r    [modsub_mont $s2 $s1 $ecc_p]
	set r_2  [modmul_mont $r $r $ecc_p $modsize]
	set h_2  [modmul_mont $h $h $ecc_p $modsize]
	set h_3  [modmul_mont $h_2 $h $ecc_p $modsize]
	set u1h2 [modmul_mont $u1 $h_2 $ecc_p $modsize]

	set u1h2_2 [modmul_mont [to_mont_domain 02  $ecc_p $modsize] $u1h2 $ecc_p $modsize]
	set x3    [modsub_mont [modsub_mont $r_2 $h_3 $ecc_p] $u1h2_2 $ecc_p]
	set y3    [modmul_mont $r [modsub_mont $u1h2 $x3 $ecc_p] $ecc_p $modsize]
	set y3    [modsub_mont $y3 [modmul_mont $s1 $h_3 $ecc_p $modsize] $ecc_p]

	set z3    [modmul_mont $h [modmul_mont $z1 $z2 $ecc_p $modsize] $ecc_p $modsize]

	return [list $x3 $y3 $z3]
}

puts "load bignum successfully!"

