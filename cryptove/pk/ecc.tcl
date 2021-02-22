#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#ecc for Tcl
#
#
#
#Willer Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#ecc_keygen
#ecc_keygen_sk
#ecc_sign
#ecc_verify
#ecc_dh
#===============================================================================

package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]

proc ecc_RandomRange { min max } {  
    # 获得[0.0,1.0)之间的随机数  
    set rd [expr rand()] 
      
    # 将$rd放大到[$min, $max)  
    set result [expr $rd * ($max - $min) + $min]  
      
    return $result  
}  
#  
#FUNC:获取[min, max)区间是随机整数  
#  
proc ecc_RandomRangeInt { min max } {  
    return [expr int([ecc_RandomRange $min $max])]  
}  
  
proc ecc_GetRandom {NumByte smin smax} { 
	set result ""
    for {set i 1} {$i<=$NumByte} {incr i} {
        set tmp [format "%02x" [ecc_RandomRangeInt $smin $smax]]
        set result [append result $tmp]  
    }
    return [string toupper $result]
}

set ecc_curve_list {
	secp160k1 {
		ecc_p  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73
		ecc_a  0000000000000000000000000000000000000000
		ecc_b  0000000000000000000000000000000000000007
		ecc_n  0000000100000000000000000001B8FA16DFAB9ACA16B6B3
		ecc_gx 3B4C382CE37AA192A4019E763036F4F5DD4D7EBB
		ecc_gy 938CF935318FDCED6BC28286531733C3F03C4FEE
	}
	secp160r1 {
		ecc_p  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF
		ecc_a  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC
		ecc_b  1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45
		ecc_n  0000000100000000000000000001F4C8F927AED3CA752257
		ecc_gx 4A96B5688EF573284664698968C38BB913CBFC82
		ecc_gy 23A628553168947D59DCC912042351377AC5FB32
	}
	secp160r2 {
		ecc_p  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73
		ecc_a  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70
		ecc_b  B4E134D3FB59EB8BAB57274904664D5AF50388BA
		ecc_n  0000000100000000000000000000351EE786A818F3A1A16B
		ecc_gx 52DCB034293A117E1F4FF11B30F7199D3144CE6D
		ecc_gy FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E
	}
	secp192k1 {
		ecc_p  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37
		ecc_a  000000000000000000000000000000000000000000000000
		ecc_b  000000000000000000000000000000000000000000000003
		ecc_n  FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D
		ecc_gx DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D
		ecc_gy 9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D
	}
	secp192r1 {
		ecc_p  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
		ecc_a  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
		ecc_b  64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
		ecc_n  FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
		ecc_gx 188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
		ecc_gy 07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
	}
	secp224k1 {
		ecc_p  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D
		ecc_a  00000000000000000000000000000000000000000000000000000000
		ecc_b  00000000000000000000000000000000000000000000000000000005
		ecc_n  000000010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7
		ecc_gx A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C
		ecc_gy 7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5
	}
	secp224r1 {
		ecc_p  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
		ecc_a  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
		ecc_b  B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
		ecc_n  FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
		ecc_gx B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
		ecc_gy BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34
	}
	secp256k1 {
		ecc_p  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
		ecc_a  0000000000000000000000000000000000000000000000000000000000000000
		ecc_b  0000000000000000000000000000000000000000000000000000000000000007
		ecc_n  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
		ecc_gx 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
		ecc_gy 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
	}
	secp256r1 {
		ecc_p  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
		ecc_a  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
		ecc_b  "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
		ecc_n  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
		ecc_gx "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
		ecc_gy "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	}
	curve25519 {
		ecc_p "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
		ecc_n "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"
		ecc_gx "0000000000000000000000000000000000000000000000000000000000000007"
		ecc_gy "20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9"

	}
	secp384r1 {
		ecc_p  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
		ecc_a  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC
		ecc_b  B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
		ecc_n  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
		ecc_gx AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
		ecc_gy 3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
	}
	secp521r1 {
		ecc_p  000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
		ecc_a  000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
		ecc_b  00000051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
		ecc_n  000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
		ecc_gx 000000C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
		ecc_gy 0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
	}
}

proc ecc_keygen {Curve} {
	global ecc_curve_list
	set ec_p  [dict get [dict get $ecc_curve_list $Curve] ecc_p]
	set ec_a  [dict get [dict get $ecc_curve_list $Curve] ecc_a]
	set ec_b  [dict get [dict get $ecc_curve_list $Curve] ecc_b]
	set ec_n  [dict get [dict get $ecc_curve_list $Curve] ecc_n]
	set ec_gx [dict get [dict get $ecc_curve_list $Curve] ecc_gx]
	set ec_gy [dict get [dict get $ecc_curve_list $Curve] ecc_gy]
    
    set PAB ${ec_p}${ec_a}${ec_b}
    set Gxy ${ec_gx}${ec_gy}
    set TmpN 0x$ec_n

	set p_len [expr [string length $ec_p]/2]
	#puts p_len=$p_len
    #100000次循环后退出，防止死循环。
    for {set i 0} {1} {incr i 1} {

        if {$i >= 1000} {
            return -code error {Error: [ecckeygen] ecc generate key time out.}
        }
        set Prikey [rem [ecc_GetRandom $p_len 0 255] $ec_n]
		set Prikey [string repeat 00 [expr $p_len-[string length $Prikey]/2]]$Prikey
        #set TmpK 0x$Prikey
        #if {($TmpK == 0) || ($TmpK >($TmpN-1))} {
        #    continue
        #}

        set Pubkey [pmul $Prikey $Gxy $PAB]
        break
    }

    return [list ${Prikey} ${Pubkey}]
}

proc ecc_keygen_sk {curve prikey} {
	global ecc_curve_list
	set ec_p  [dict get [dict get $ecc_curve_list $curve] ecc_p]
	set ec_a  [dict get [dict get $ecc_curve_list $curve] ecc_a]
	set ec_b  [dict get [dict get $ecc_curve_list $curve] ecc_b]
	set ec_n  [dict get [dict get $ecc_curve_list $curve] ecc_n]
	set ec_gx [dict get [dict get $ecc_curve_list $curve] ecc_gx]
	set ec_gy [dict get [dict get $ecc_curve_list $curve] ecc_gy]
	
    set PAB ${ec_p}${ec_a}${ec_b}

	return [pmul $prikey ${ec_gx}${ec_gy} $PAB]

}

proc ecc_sign {Curve Random Prikey Ehash} {
	global ecc_curve_list
	set ec_p  [dict get [dict get $ecc_curve_list $Curve] ecc_p]
	set ec_a  [dict get [dict get $ecc_curve_list $Curve] ecc_a]
	set ec_b  [dict get [dict get $ecc_curve_list $Curve] ecc_b]
	set ec_n  [dict get [dict get $ecc_curve_list $Curve] ecc_n]
	set ec_gx [dict get [dict get $ecc_curve_list $Curve] ecc_gx]
	set ec_gy [dict get [dict get $ecc_curve_list $Curve] ecc_gy]
    
    set PAB ${ec_p}${ec_a}${ec_b}
    set Gxy ${ec_gx}${ec_gy}
    
	set TmpN 0x$ec_n 
	set TmpE 0x$Ehash
	set TmpK 0x$Random 

	set PByteLen [expr [string length $ec_p]/2]
	set NByteLen [expr [string length $ec_n]/2]
	set EByteLen [expr [string length $Ehash]/2]
	#puts plen_$PByteLen
	#puts nlen_$NByteLen
	#puts elen_$EByteLen

	if {$TmpN < $TmpE} {
		return -code error {Error: ECDSA Ehash length error}	
	}

	if {$EByteLen < $NByteLen} {
		set temp_e [string repeat 00 [expr $NByteLen - $EByteLen]]$Ehash
	} else {
        set temp_e $Ehash
    }

	if {($TmpK == 0) || ($TmpK > ($TmpN-1))} {
		return -code error {Error: ECDSA Random error}	
	}
	#TODO length of random number

	#puts $Random
    #4. 计算椭圆曲线点(x1, y1) =[k]G
    set x1y1 [pmul $Random $Gxy $PAB]
	set x1 [string range $x1y1 0 [expr $PByteLen*2 - 1]]
	#puts x1y1_$x1y1
	#puts x1_$x1
    #5. 计算r = x1 mod n, 若r=0 ...
    set r [rem $x1 $ec_n]
    set tmpR 0x$r
    if {$tmpR == 0} {
        return -code error {Error: ECDSA r==0}
    }

    set rlen [string length $r]
    set r [string repeat 00 [expr $NByteLen -$rlen/2]]$r
	#puts r_$r
	
    #A6. 计算s=k^-1 * (ehash+r*dA) mod n 
	set rdA [modmul $r $Prikey $ec_n]
	set e_rdA [modadd $temp_e $rdA $ec_n]
	set k_inv [modinv $Random $ec_n]
	set s [modmul $k_inv $e_rdA $ec_n]
    set slen [string length $s]
    set s [string repeat 00 [expr $NByteLen-$slen/2]]$s
	#puts s_$s
    
    return [list ${r} ${s}]
}

proc ecc_verify {Curve Pubkey RS Ehash} {
	global ecc_curve_list
	set ec_p  [dict get [dict get $ecc_curve_list $Curve] ecc_p]
	set ec_a  [dict get [dict get $ecc_curve_list $Curve] ecc_a]
	set ec_b  [dict get [dict get $ecc_curve_list $Curve] ecc_b]
	set ec_n  [dict get [dict get $ecc_curve_list $Curve] ecc_n]
	set ec_gx [dict get [dict get $ecc_curve_list $Curve] ecc_gx]
	set ec_gy [dict get [dict get $ecc_curve_list $Curve] ecc_gy]
    
    set PAB ${ec_p}${ec_a}${ec_b}
    set Gxy ${ec_gx}${ec_gy}

	set PByteLen [expr [string length $ec_p]/2]
	set NByteLen [expr [string length $ec_n]/2]
	set EByteLen [expr [string length $Ehash]/2]
	set SByteLen [expr [string length $RS]/2]
	#puts plen_$PByteLen
	#puts nlen_$NByteLen
	#puts elen_$EByteLen

    set TmpN 0x$ec_n
	set TmpE 0x$Ehash

	if {$TmpN < $TmpE} {
		return -code error {Error: ECDSA Ehash length error}	
	}

	#puts $Ehash
	#if {$EByteLen < $NByteLen} {
		set temp_e [string repeat 00 [expr $NByteLen - $EByteLen]]$Ehash
	#} 

    set R [string range $RS 0 [expr $SByteLen/2*2-1]]
    set S [string range $RS [expr $SByteLen/2*2] end]
	#puts r_$R
	#puts s_$S

    set TmpR 0x$R
    set TmpS 0x$S

    if {($TmpR == 0) || ($TmpR >= $TmpN)} {
        return -code error {Error:  The value of arg R(RS) should be in [1 n-1].}
    }

    if {($TmpS == 0) || ($TmpS >= $TmpN)} {
        return -code error {Error:  The value of arg S(RS) should be in [1 n-1].}
    }
    
	# w = s^-1 mode n
    #B5. t = (r'+s') mod n, 若t=0 ...
	set w  [modinv $S $ec_n]
	set u1 [modmul $temp_e $w $ec_n]
	set u2 [modmul $R $w $ec_n]

	#puts $temp_e
	#puts $w
	#puts $u1
	#puts $u2
    #B6. (x1', y1') = [s']G + [t]PA
    set x1y1 [mpmul $u1 $Gxy $u2 $Pubkey $PAB]

    #B7. R = (e'+x1') mod n, r ?= R
	set x1y1len [expr [string length $x1y1]/2]
	puts x1y1len_$x1y1len
    set R1 [string range $x1y1 0 [expr $x1y1len/2*2-1]]
    set R1 [string repeat 00 [expr $NByteLen-$x1y1len/2]]$R1
    set TmpR1 0x$R1
    set TmpR 0x$R
	puts r1_$TmpR1
	puts r_$TmpR
    if {$TmpR1 != $TmpR} {
        return -1
    } else {
        return 0
    }

}

proc ecc_dh {curve prikey pubkey} {
	global ecc_curve_list
	set ec_p  [dict get [dict get $ecc_curve_list $curve] ecc_p]
	set ec_a  [dict get [dict get $ecc_curve_list $curve] ecc_a]
	set ec_b  [dict get [dict get $ecc_curve_list $curve] ecc_b]
	set ec_n  [dict get [dict get $ecc_curve_list $curve] ecc_n]
	set ec_gx [dict get [dict get $ecc_curve_list $curve] ecc_gx]
	set ec_gy [dict get [dict get $ecc_curve_list $curve] ecc_gy]
	
    set PAB ${ec_p}${ec_a}${ec_b}

	set xlen [expr [string length $ec_gx]/2]

	return [string range [pmul $prikey $pubkey $PAB] 0 [expr $xlen*2-1]]

}

proc pmul_ecc256 {k point} {
	global ecc_curve_list
	set curve secp256r1

	set ec_p  [dict get [dict get $ecc_curve_list $curve] ecc_p]
	set ec_a  [dict get [dict get $ecc_curve_list $curve] ecc_a]
	set ec_b  [dict get [dict get $ecc_curve_list $curve] ecc_b]
	set ec_n  [dict get [dict get $ecc_curve_list $curve] ecc_n]
	set ec_gx [dict get [dict get $ecc_curve_list $curve] ecc_gx]
	set ec_gy [dict get [dict get $ecc_curve_list $curve] ecc_gy]
	
    set PAB ${ec_p}${ec_a}${ec_b}

	set xlen [expr [string length $ec_gx]/2]

	return [pmul $k $point $PAB]
}

proc padd_ecc256 {p1 p2} {
	global ecc_curve_list
	set curve secp256r1

	set ec_p  [dict get [dict get $ecc_curve_list $curve] ecc_p]
	set ec_a  [dict get [dict get $ecc_curve_list $curve] ecc_a]
	set ec_b  [dict get [dict get $ecc_curve_list $curve] ecc_b]
	set ec_n  [dict get [dict get $ecc_curve_list $curve] ecc_n]
	set ec_gx [dict get [dict get $ecc_curve_list $curve] ecc_gx]
	set ec_gy [dict get [dict get $ecc_curve_list $curve] ecc_gy]
	
    set PAB ${ec_p}${ec_a}${ec_b}
	return [padd $p1 $p2 $PAB]
}

proc ecdsa_sign {hmode curve k msg} {
    global ecc_curve_list
    puts $hmode

    set trunkbit 0
    if {$curve == "secp224k1"} {
        set h [${hmode}_process ""]
        set hashsize [expr [string length $h] / 2 * 8]
        set trunkbit [expr $hashsize - 225]
    }


    set klen [expr [string length $k]/2]
    set random 00000000[rand [expr $klen-4] 0 256]
    puts m_[${hmode}_process $msg]
    if {$trunkbit == 0} {
        set mhash [string range [${hmode}_process $msg] 0 [expr $klen*2 - 1]]
    } else {
        set ec_n [dict get [dict get $ecc_curve_list $curve] ecc_n]
        set mhash [sft R [${hmode}_process $msg] $trunkbit]
        set mhash [rem $mhash $ec_n]
    }

    return [ecc_sign $curve $random $k $mhash]
}

proc ecdsa_verify {hmode curve Q sig msg} {
    global ecc_curve_list
    puts $hmode

    set trunkbit 0
    if {$curve == "secp224k1"} {
        set h [${hmode}_process ""]
        set hashsize [expr [string length $h] / 2 * 8]
        set trunkbit [expr $hashsize - 225]
    }

    set klen [expr [string length $Q]/2/2]
    if {$trunkbit == 0} {
        set mhash [string range [${hmode}_process $msg] 0 [expr $klen*2 - 1]]
    } else {
        set ec_n [dict get [dict get $ecc_curve_list $curve] ecc_n]
        set mhash [sft R [${hmode}_process $msg] $trunkbit]
        set mhash [rem $mhash $ec_n]
    }
    set dout [ecc_verify $curve $Q $sig $mhash]

    return $dout
}

