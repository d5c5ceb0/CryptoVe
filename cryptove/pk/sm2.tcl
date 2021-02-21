#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#sm2 for Tcl
#
#实现了256位、素数域SM2函数功能，包括生成Z值，生成E值，密钥派生kdf，密钥生成，签名验签，加密解密，
#密钥交换。
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#1. sm2_getz:   生成z值，   sm2_getz ID Pubkey
#2. sm2_gete:   生成e值，   sm2_gete Z M 
#3. sm2_kdf:    密钥派生，  sm2_kdf Z OByteLen
#4. sm2_keygen: 密钥生成，  sm2_keygen
#5. sm2_sig:    签名，      sm2_sig Random Prikey Ehash
#6. sm2_ver:    验签，      sm2_ver Pubkey RS Ehash
#7. sm2_enc:    加密，      sm2_enc Random Pubkey M
#8. sm2_dec：   解密，      sm2_dec Prikey C
#9. sm2_kex:    密钥交换，  sm2_kex Role OutKeyByteLen ZSelf ZSide KeySelf RKeySelf PubKeySide RPubKeySide
#===============================================================================


package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]


proc sm2_RandomRange { min max } {  
    # 获得[0.0,1.0)之间的随机数  
    set rd [expr rand()] 
      
    # 将$rd放大到[$min, $max)  
    set result [expr $rd * ($max - $min) + $min]  
      
    return $result  
}  
#  
#FUNC:获取[min, max)区间是随机整数  
#  
proc sm2_RandomRangeInt { min max } {  
    return [expr int([sm2_RandomRange $min $max])]  
}  
  
proc sm2_GetRandom {NumByte smin smax} {
    set result ""
    for {set i 1} {$i<=$NumByte} {incr i} {
        set tmp [format "%02x" [sm2_RandomRangeInt $smin $smax]]
        set result [append result $tmp]  
    }
    return [string toupper $result]
}

#十进制转十六进制
proc sm2_hex {dec} {
	set ret ""
	while {$dec} {
		set ret [format %x [expr $dec % 16]]$ret
		set dec [expr $dec / 16]
	}
	
	set len [string length $ret]
	if {$len%2} {
		set ret 0$ret
	}
	return $ret
}

#
#设置默认椭圆曲线参数(P A B N Gx Gy H),将其设置为国密推荐椭圆曲线参数。
#通过改写sm2_p, sm2_a, sm2_b, sm2_n, sm2_gx, sm2_gy, sm2_h，可以在自己的脚本里随意设置椭圆曲线参数。
#
#参数P
set sm2_p FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
#参数A
set sm2_a FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
#参数B
set sm2_b 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
#参数N
set sm2_n FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
#参数Xg
set sm2_gx 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
#参数Yg
set sm2_gy BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
#参数h
set sm2_h 00000001


#=============================================================================================
#sm2_getz
#
#生成SM2算法中的Z值，可用于签名验签，密钥交换
#
#ID      用于生成Z值的ID信息
#pubkey  SM2公钥Px||Py
#
#返回值为列表，列表第一个值表示返回状态，第二个值表示返回数据。
#可以先查询返回状态，再对相应的返回数据处理。
#{0, Z值}
#{1，错误信息}
#
#=============================================================================================
proc sm2_getz {ID Pubkey} {

    #加载全局变量
    global sm2_a sm2_b sm2_gx sm2_gy

    #对输入参数进行检查
    #ID的字符串长度，真实ID长度需要再除以2
    set IDByteLen [string length $ID]
    if {($IDByteLen % 2) || ($IDByteLen == 0)} {
        return -code error {Error: [sm2_getz ID Pubkey] The length of arg ID should be even and not 0.}
    }

    set KeyByteLen [string length $Pubkey]
    if {$KeyByteLen != 64*2} {
        return -code error {Error: [sm2_getz ID Pubkey] The length of arg Pubkey should be 64 bytes.}
    }

    #ID比特长度
    set IDBitLen [format %04x [expr ${IDByteLen} / 2 * 8]]

    #计算Z = H256(IDlen||ID||a||b||Gx||Gy||Px||Py)
    return [sm3 ${IDBitLen}${ID}${sm2_a}${sm2_b}${sm2_gx}${sm2_gy}${Pubkey}]

}


#==============================================================================================
#sm2_gete
#
#生成SM2算法中的E值，用于签名验签运算
#
#Z  签名验签用到的Z值，可使用sm2_getz生成
#M  签名的消息
#
#返回值为列表，列表第一个值表示返回状态，第二个值表示返回数据。
#可以先查询返回状态，再对相应的返回数据处理。
#{0, E值}
#{1，错误信息}
#==============================================================================================
proc sm2_gete {Z M} {

    #对输入参数进行检查
    set ZByteLen [string length $Z]
    if {$ZByteLen != 32*2} {
        return -code error {Error: [sm2_gete Z M] The length of arg Z should be 32 bytes.}
    }

    set MByteLen [string length $M]
    if {($MByteLen % 2) || ($MByteLen == 0)} {
        return -code error {Error: [sm2_gete Z M] The length of arg M should be even and not 0.}
    }

    #计算E = Hv(Z||M)
    return [sm3 ${Z}${M}]

} 


#===============================================================================================
#sm2_kdf
#
#SM2密钥派生函数
#
#Z         用于派生密钥的输入数据
#OByteLen  需要派生的密钥字节长度
#
#返回值为列表，列表第一个值表示返回状态，第二个值表示返回数据。
#可以先查询返回状态，再对相应的返回数据处理。
#{0, 派生密钥}
#{1，错误信息}
#===============================================================================================
proc sm2_kdf {Z OByteLen} {

    #对输入参数进行检查
    set ZByteLen [string length $Z]
    if {($ZByteLen % 2) || ($ZByteLen == 0)} {
        return -code error {Error: [sm2_kdf Z OByteLen] The length of arg Z should be even and not 0.}
    }

    if {$OByteLen == 0} {
        return -code error {"Usage: sm2_kdf Z OByteLen. The length of arg OByteLen should not be 0.}
    }

    set ct 1
    set out ""
    for {set i 0} {$i < ($OByteLen+31)/32} {incr i 1} {
        set ct2 [format %08x $ct]
        append out [sm3 ${Z}$ct2]
        incr ct 1
    }
    
    return [string range $out 0 [expr $OByteLen*2-1]]
}


#==============================================================================================
#sm2_keygen 
#
#SM2密钥生成
#
#
#返回值为列表，列表第一个值表示返回状态，第二个值表示返回数据。
#可以先查询返回状态，再对相应的返回数据处理。
#{0, 密钥对}
#{1，错误信息}
#==============================================================================================
proc sm2_keygen {} {

    #加载全局变量
    global sm2_p sm2_a sm2_b sm2_n sm2_gx sm2_gy
    
    set PAB ${sm2_p}${sm2_a}${sm2_b}
    set Gxy ${sm2_gx}${sm2_gy}
    set TmpN 0x$sm2_n

    #100000次循环后退出，防止死循环。
    for {set i 0} {1} {incr i 1} {

        if {$i >= 100} {
            return -code error {Error: [sm2_keygen] sm2 generate key time out.}
        }
        set Prikey [sm2_GetRandom 32 0 255]
        set TmpK 0x$Prikey
        if {($TmpK == 0) || ($TmpK >($TmpN-2))} {
            continue
        }

        set Pubkey [pmul $Prikey $Gxy $PAB]
        break
    }

    return [list ${Prikey} ${Pubkey}]
}

proc sm2_keygen_sk {prikey} {
    global sm2_p sm2_a sm2_b sm2_n sm2_gx sm2_gy

    set PAB ${sm2_p}${sm2_a}${sm2_b}
    set Gxy ${sm2_gx}${sm2_gy}
    set Pubkey [pmul $prikey $Gxy $PAB]

	return $Pubkey

}


#==============================================================================================
#sm2_sig
#
#SM2签名运算
#
#Random  输入随机数
#Prikey  私钥
#Ehash   签名E值
#
#返回值为列表，列表第一个值表示返回状态，第二个值表示返回数据。
#可以先查询返回状态，再对相应的返回数据处理。
#{0, 签名数据}
#{1，错误信息}
#{2, Random在[1, n-1]之外}, 需要重新输入随机数
#==============================================================================================
proc sm2_sig {Random Prikey Ehash} {
    
    #加载全局变量
    global sm2_p sm2_a sm2_b sm2_n sm2_gx sm2_gy

    #对输入参数进行检查
    set RByteLen [string length $Random]
    if {$RByteLen != 32*2} {
        return -code error {Error: [sm2_sig Random Prikey Ehash] The length of arg Random should be 32 bytes.}
    }
    set TmpR 0x$Random
    set TmpN 0x$sm2_n
    if {($TmpR == 0) || ($TmpR >= $TmpN)} {
        return -code error {Error: [sm2_sig Random Prikey Ehash] The value of arg Random should be in [1 n-1].}
    }

    set KByteLen [string length $Prikey]
    if {$KByteLen != 32*2} {
        return -code error {Error: [sm2_sig Random Prikey Ehash] The length of arg Prikey should be 32 bytes.}
    }

    set EByteLen [string length $Ehash]
    if {$EByteLen != 32*2} {
        return -code error {Error: [sm2_sig Random Prikey Ehash] The length of arge Ehash should be 32 bytes.}
    }

    #曲线参数
    set PAB ${sm2_p}${sm2_a}${sm2_b}
    set Gxy ${sm2_gx}${sm2_gy}


    #A4. 计算椭圆曲线点(x1, y1) =[k]G
    set x1y1 [pmul $Random $Gxy $PAB]

    #A5. 计算r = (e+x1) mod n, 若r=0或r+k=n ...
    set r [modadd $Ehash [string range $x1y1 0 63] $sm2_n]
    set r_hex 0x$r
    set raddk 0x[add $r $Random]
    if {($r_hex == 0) || ($raddk == $sm2_n)} {
        return -code error {Error: [sm2_sig Random Prikey Ehash] A4: r==0 or r+k==n}
    }
    set rlen [string length $r]
    set r [string repeat 00 [expr 32-$rlen/2]]$r

    #A6. 计算s=(1+dA)^-1 * (k-r*dA) mod n 
    set inv_1_add_da [modinv [modadd $Prikey 01 $sm2_n] $sm2_n]
    puts inv_$inv_1_add_da
    set mul_r_da [modmul $r $Prikey $sm2_n]
    set sub_k_mulrda [modsub $Random $mul_r_da $sm2_n]

    set s [modmul $inv_1_add_da $sub_k_mulrda $sm2_n]
    set slen [string length $s]
    set s [string repeat 00 [expr 32-$slen/2]]$s

    return ${r}${s}
}

#==============================================================================================
#sm2_ver
#
#SM2验签
#
#pubkey 公钥
#RS     签名数据
#Ehash  签名E值
#
#返回值为列表，列表第一个值表示返回状态，第二个值表示返回数据。
#可以先查询返回状态，再对相应的返回数据处理。
#{0, 正确信息}
#{1，错误信息}
#==============================================================================================
proc sm2_ver {Pubkey RS Ehash} {

    #加载全局变量
    global sm2_p sm2_a sm2_b sm2_n sm2_gx sm2_gy

    set PByteLen [string length $Pubkey]
    if {$PByteLen != 64*2} {
        return -code error {Error: [sm2_ver Pubkey RS Ehash] The length arg Pubkey should be 64 bytes.}
    }

    set RSByteLen [string length $RS]
    if {$RSByteLen != 64*2} {
        return -code error {Error: [sm2_ver Pubkey RS Ehash] The length arg RS should be 64 bytes.}
    }

    set EByteLen [string length $Ehash]
    if {$EByteLen != 32*2} {
        return -code error {Error: [sm2_ver Pubkey RS Ehash] The length arg Ehash should be 32 bytes.}
    }

    set PAB ${sm2_p}${sm2_a}${sm2_b}
    set Gxy ${sm2_gx}${sm2_gy}

    set R [string range $RS 0 63]
    set S [string range $RS 64 127]

    set TmpR 0x$R
    set TmpS 0x$S
    set TmpN 0x$sm2_n
    if {($TmpR == 0) || ($TmpR >= $TmpN)} {
        return -code error {Error: [sm2_ver Pubkey RS Ehash] The value of arg R(RS) should be in [1 n-1].}
    }

    if {($TmpS == 0) || ($TmpS >= $TmpN)} {
        return -code error {Error: [sm2_ver Pubkey RS Ehash] The value of arg S(RS) should be in [1 n-1].}
    }
    
    #B5. t = (r'+s') mod n, 若t=0 ...
    set t [modadd $R $S $sm2_n]
    set Tmpt 0x$t
    if {$Tmpt == 0} {
        return -code error {Error: [sm2_ver Pubkey RS Ehash] B5: t==0.}
    }

    #B6. (x1', y1') = [s']G + [t]PA
    set tByteLen [string length $t]
    set t [string repeat 00 [expr 32-$tByteLen/2]]$t
    set x1y1 [mpmul $S $Gxy $t $Pubkey $PAB]

    #B7. R = (e'+x1') mod n, r ?= R
    set R1 [modadd $Ehash [string range $x1y1 0 63] $sm2_n]
    set TmpR1 0x$R1
    set TmpR 0x$R
    if {$TmpR1 != $TmpR} {
        return -code error {Error: [sm2_ver Pubkey RS Ehash] verify error.}
    } else {
        return 0
    }

}



#==============================================================================================
#sm2_kex
#
#密钥交换
#
#Role          角色 0-发起方， 1-响应方
#OutKeyByteLen 输出协商密钥的字节长度
#ZSelf         自己的ID生成的Z值，可以通过sm2getz函数生成
#ZSide         对方的ID生成的Z值，可以通过sm2getz函数生成
#KeySelf       自己的密钥对${prikey}${pubkey}
#RKeySelf      自己的临时密钥对${rprikey}${rpubkey}，可以通过sm2keygen函数生成
#PubKeySide    对方的公钥
#RPubKeySide   对方的临时公钥
#
#返回值为列表，列表第一个值表示返回状态，第二个值表示返回数据。
#可以先查询返回状态，再对相应的返回数据处理。
#{0, 协商密钥，选项S1b, 选项S2a}
#{1，错误信息}
#==============================================================================================
proc sm2_kex {Role OutKeyByteLen ZSelf ZSide KeySelf RKeySelf PubKeySide RPubKeySide} {

    #加载全局变量
    global sm2_p sm2_a sm2_b sm2_n sm2_gx sm2_gy sm2_h
    
    set KByteLen [string length $KeySelf]
    if {$KByteLen != 96*2} {
        return -code error {Error: [sm2_kex Role OutKeyByteLen ZSelf ZSide KeySelf RKeySelf PubKeySide RPubKeySide] The length of arg KeySelf should be 96 bytes.}
    }

    set KByteLen [string length $RKeySelf]
    if {$KByteLen != 96*2} {
        return -code error {Error: [sm2_kex Role OutKeyByteLen ZSelf ZSide KeySelf RKeySelf PubKeySide RPubKeySide] The length of arg RKeySelf should be 96 bytes.}
    }

    set KByteLen [string length $PubKeySide]
    if {$KByteLen != 64*2} {
        return -code error {Error: [sm2_kex Role OutKeyByteLen ZSelf ZSide KeySelf RKeySelf PubKeySide RPubKeySide] The length of arg PubKeySide should be 64 bytes.}
    }

    set KByteLen [string length $RPubKeySide]
    if {$KByteLen != 64*2} {
        return -code error {Error: [sm2_kex Role OutKeyByteLen ZSelf ZSide KeySelf RKeySelf PubKeySide RPubKeySide] The length of arg RPubKeySide should be 64 bytes.}
    }
    
    set PAB ${sm2_p}${sm2_a}${sm2_b}
    set Gxy ${sm2_gx}${sm2_gy}


    #自己的密钥
    set dSelf [string range $KeySelf 0 63]
    set PxSelf [string range $KeySelf 64 127]
    set PySelf [string range $KeySelf 128 191]
    #自己的临时密钥
    set rdSelf [string range $RKeySelf 0 63]
    set rPxSelf [string range $RKeySelf 64 127]
    set rPySelf [string range $RKeySelf 128 191]

    #对方的公钥
    set PxSide [string range $PubKeySide 0 63]
    set PySide [string range $PubKeySide 64 127]

    #对方的临时公钥
    set rPxSide [string range $RPubKeySide 0 63]
    set rPySide [string range $RPubKeySide 64 127]

    #w = [[long2n]/2]-1
    set nBitLen [expr [string length $sm2_n]/2*8]
    set w [expr $nBitLen/2-1]
    
    #
    set TmprPxSelf 0x$rPxSelf
    set rPxSelf2 [expr (2 ** $w) + ($TmprPxSelf & (2 ** $w - 1))]
    set rPxSelf2 [sm2_hex $rPxSelf2]

    #ta = (da + x'*ra) mod n
    set tSelf [modmul $rPxSelf2 $rdSelf $sm2_n]
    set tSelf [modadd $dSelf $tSelf $sm2_n]

    #
    set TmprPxSide 0x$rPxSide
    set rPxSide2 [expr (2 ** $w) + ($TmprPxSide & (2 ** $w - 1))]
    set rPxSide2 [sm2_hex $rPxSide2]

    set tlen [string length $rPxSide2]
    set rPxSide2 [string repeat 00 [expr 32-$tlen/2]]$rPxSide2
    set U [pmul $rPxSide2 ${rPxSide}$rPySide $PAB]
    set U [padd ${PxSide}$PySide $U $PAB]
    set tSelf [mul $sm2_h $tSelf]

    set tlen [string length $tSelf]
    set tSelf [string repeat 00 [expr 32-$tlen/2]]$tSelf

    set U [pmul $tSelf $U $PAB]
    set xu [string range $U 0 63]
    set yu [string range $U 64 127]

    if {$Role == 0} {
        set outKey [sm2_kdf ${U}${ZSelf}${ZSide} $OutKeyByteLen]
        set tmps [sm3 ${xu}${ZSelf}${ZSide}${rPxSelf}${rPySelf}${rPxSide}${rPySide}]
    } else {
        set outKey [sm2_kdf ${U}${ZSide}${ZSelf} $OutKeyByteLen]
        set tmps [sm3 ${xu}${ZSide}${ZSelf}${rPxSide}${rPySide}${rPxSelf}${rPySelf}]
    }

    set s1b [sm3 02${yu}${tmps}]
    set s2a [sm3 03${yu}${tmps}]

    return [list $outKey $s1b $s2a]
}


#==============================================================================================
#sm2_enc
#
#密钥加密
#
#Random 随机数，在[1 n-1]之间
#Pubkey 公钥
#M 输入明文消息
#
#返回值为列表，列表第一个值表示返回状态，第二个值表示返回数据。
#可以先查询返回状态，再对相应的返回数据处理。
#{0, 密文数据}
#{1，错误信息}
#{2, Random在[1, n-1]之外}, 需要重新输入随机数
#==============================================================================================
proc sm2_enc {Random Pubkey M} {

    #加载全局变量
    global sm2_p sm2_a sm2_b sm2_n sm2_gx sm2_gy

    #输入检查
    set RByteLen [string length $Random]
    if {$RByteLen != 32*2} {
        return -code error {Error: [sm2_enc Random Pubkey M] Arg Random should be 32 bytes.}
    }
    set TmpR 0x$Random
    set TmpN 0x$sm2_n
    if {($TmpR == 0) || ($TmpR >= $TmpN)} {
        return -code error {Error: [sm2_enc Random Pubkey M] Arg Random should be in [1 n-1].}
    }
    
    set PByteLen [string length $Pubkey]
    if {$PByteLen != 64*2} {
        return -code error {Error: [sm2_enc Random Pubkey M] Arg Pubkey should be 64 bytes.}
    }

    set MByteLen [string length $M]
    if {($MByteLen % 2) ||($MByteLen == 0)} {
        return -code error {Error: [sm2_enc Random Pubkey M] The length of arg M should be even and not be 0.}
    }
    
    set PAB ${sm2_p}${sm2_a}${sm2_b}
    set Gxy ${sm2_gx}${sm2_gy}

    set MByteLen [expr $MByteLen/2]

    #计算C1
    set C1 [pmul $Random $Gxy $PAB]

    #计算C2
    set x2y2 [pmul $Random $Pubkey $PAB]

    set t [sm2_kdf $x2y2 $MByteLen]
    set tmpt 0x$t
    if {$tmpt == 0} {
        return -code error {Error: [sm2_enc Random Pubkey M] kdf t == 0 error.}
    }
    set C2 ""
    for {set i 0} {$i < ${MByteLen}*2} {incr i 2} {
        append C2 [format %02X [expr 0x[string range ${M} $i $i+1] ^ 0x[string range ${t} $i $i+1]]]
    }

    #计算C3
    set x2My2 [string range $x2y2 0 63]${M}[string range $x2y2 64 127]
    set C3 [sm3 $x2My2]

    return ${C1}${C3}${C2}

}


#==============================================================================================
#sm2_dec
#
#密钥解密
#
#Prikey 私钥
#C 输入密文消息
#
#返回值为列表，列表第一个值表示返回状态，第二个值表示返回数据。
#可以先查询返回状态，再对相应的返回数据处理。
#{0, 明文数据}
#{1，错误信息}
#==============================================================================================
proc sm2_dec {Prikey C} {
       
    #加载全局变量
    global sm2_p sm2_a sm2_b
    
    #输入检查
    set KByteLen [string length $Prikey]
    if {$KByteLen != 32*2} {
        return -code error {Error: [sm2_dec Prikey C] Arg Prikey should be 32 bytes.}
    }

    set CByteLen [string length $C]
    if {($CByteLen %2) || ($CByteLen <= 96*2)} {
        return -code error {Error: [sm2_dec Prikey C] Arg C should be even and be larger than 96 bytes.}
    }
    set CByteLen [expr $CByteLen/2]

    set PAB ${sm2_p}${sm2_a}${sm2_b}

    set C1 [string range $C 0 127]
    set C3 0x[string range $C 128 191]
    set C2 [string range $C 192 end]
    
    #验证C1是否在曲线上???


    #计算M
    set MByteLen [expr $CByteLen - 64 - 32]
    set x2y2 [pmul $Prikey $C1 $PAB]
    set t [sm2_kdf $x2y2 $MByteLen]
    set tmpt 0x$t
    if {$tmpt == 0} {
        return -code error {ERROR: [sm2_dec Prikey C] kdf t == 0 error.}   
    }
    set M ""
    for {set i 0} {$i < ${MByteLen}*2} {incr i 2} {
        append M [format %02X [expr 0x[string range ${C2} $i $i+1] ^ 0x[string range ${t} $i $i+1]]]
    }

    #计算C3
    set x2My2 [string range $x2y2 0 63]${M}[string range $x2y2 64 127]
    set u 0x[sm3 $x2My2]


    if {$u != $C3} {
        return -code error {Error: [sm2_dec Prikey C] decrypt error.}
    } else {
        return $M
    }
}


proc sm2isp {point} {
    
    #加载全局变量
    global sm2_p sm2_a sm2_b

    set PAB ${sm2_p}${sm2_a}${sm2_b}

    ispoint $point $PAB
}

proc sm2padd {point1 point2} {
    
    #加载全局变量
    global sm2_p sm2_a sm2_b

    set PAB ${sm2_p}${sm2_a}${sm2_b}

    padd $point1 $point2 $PAB
}

proc sm2pmul {k point} {
    
    #加载全局变量
    global sm2_p sm2_a sm2_b

    set pab ${sm2_p}${sm2_a}${sm2_b}

    pmul $k $point $pab
}

proc sm2mpmul {k1 point1 k2 point2} {
    
    #加载全局变量
    global sm2_p sm2_a sm2_b

    set pab ${sm2_p}${sm2_a}${sm2_b}

    mpmul $k1 $point1 $k2 $point2 $pab
}

puts "load sm2 successfully!"
