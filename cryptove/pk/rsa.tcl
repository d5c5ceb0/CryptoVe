#===============================================================================
#rsa api for TCL
#
#rsa api
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#函数介绍
#1. rsa_keygen: 生成密钥，  rsa_keygen e nlen 
#2. rsa_enc :   加密或签名，rsa_enc e n M 
#3. rsa_dec:    解密或验签，rsa_dec d n C
#4. rsa_crt:    CRT运算，   rsa_crt p q dP dQ Qinv C
#=============================================================================================

package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto.so]

proc rsa_RandomRange { min max } {  
    # 获得[0.0,1.0)之间的随机数  
    set rd [expr rand()] 
      
    # 将$rd放大到[$min, $max)  
    set result [expr $rd * ($max - $min) + $min]  
      
    return $result  
}  
#  
#FUNC:获取[min, max)区间是随机整数  
#  
proc rsa_RandomRangeInt { min max } {  
    return [expr int([rsa_RandomRange $min $max])]  
}  
  
proc rsa_GetRandom {NumByte smin smax} {
    set result ""
    for {set i 1} {$i<=$NumByte} {incr i} {
        set tmp [format "%02x" [rsa_RandomRangeInt $smin $smax]]
        set result [append result $tmp]  
    }
    return [string toupper $result]
}
#=============================================================================================
#rsa_keygen
#
#RSA密钥生成
#
#e  公钥e 
#nlen 生成密钥的长度，模数n的字节长度
#
#{e, n, d, p, q, dP, dQ, Qinv}
#
#=============================================================================================
proc rsa_keygen {e nlen} {


    #对输入参数进行检查
    set eByteLen [string length $e]
    if {($eByteLen % 2) || ($eByteLen == 0)} {
        return -code error {Error(rsa_keygen): [rsa_keygen e nlen] The length of arg e should be even and not be 0.}
    }

    if {$nlen == 0} {
        return -code error {Error(rsa_keygen): [rsa_keygen e nlen] The length of arg nlen should not be 0.}
    }

    set rsa_times 0
    while {1} {

        if {$rsa_times >= 100} {
            return -code error {Error: [rsa_keygen e nlen] rsa generate key time out.}
        }

        #生成素数p
        while {1} {
            set head [rsa_GetRandom 1 0 255]
            set head [format %02x [expr 0x$head | 0x80]]
            set body [rsa_GetRandom [expr $nlen/2-1] 0 255]

            set p [genprime ${head}${body}]
            set ret [isprime $p]
            if {$ret == 01} {
                break   
            }
        }


        #生成素数q
        while {1} {
            set head [rsa_GetRandom 1 0 255]
            set head [format %02x [expr 0x$head | 0x80]]
            set body [rsa_GetRandom [expr $nlen/2-1] 0 255]

            set q [genprime ${head}${body}]
            if {$p == $q} {
                continue
            }
            set ret [isprime $q]
            if {$ret == 01} {
                break   
            }
        }

        #欧拉函数
        set w [mul [sub $p 01] [sub $q 01]]
        set ret [gcd $e $w]
        if {$ret == 01} {
            break
        }

        incr rsa_times 1
    }

    #私钥D
    set d [modinv $e $w]

    #模数N
    set n [mul $p $q]

    #DP
    set dP [rem $d [sub $p 01]]
    #DQ
    set dQ [rem $d [sub $q 01]]
    #QInv
    set Qinv [modinv $q $p]

    return [list $e $n $d ${p} ${q} ${dP} ${dQ} ${Qinv}]
}


proc rsakeygen_pq {e p q} {


    #对输入参数进行检查
    set eByteLen [string length $e]
    if {($eByteLen % 2) || ($eByteLen == 0)} {
        return -code error {Error(rsakeygen_pq): [rsa_keygen e p q] The length of arg e should be even and not be 0.}
    }

    set pByteLen [string length $p]
    if {($pByteLen % 2) || ($pByteLen == 0)} {
        return -code error {Error(rsakeygen_pq): [rsa_keygen e p q] The length of arg p should be even and not be 0.}
    }

    set qByteLen [string length $q]
    if {($qByteLen % 2) || ($qByteLen == 0)} {
        return -code error {Error(rsakeygen_pq): [rsa_keygen e p q] The length of arg q should be even and not be 0.}
    }

    #欧拉函数
    set w [mul [sub $p 01] [sub $q 01]]
    set ret [gcd $e $w]
    if {$ret != 01} {
        return -code error {Error(rsakeygen_pq): [rsa_keygen e p q] The value of (p-1)*(q-1) is not coprime with e.}
    }

    #私钥D
    set d [modinv $e $w]

    #模数N
    set n [mul $p $q]

    #DP
    set dP [rem $d [sub $p 01]]
    #DQ
    set dQ [rem $d [sub $q 01]]
    #QInv
    set Qinv [modinv $q $p]

    return [list $e $n $d ${p} ${q} ${dP} ${dQ} ${Qinv}]
}
#=============================================================================================
#rsa_enc
#
#RSA加密或签名
#
#e  公钥e 
#n  模数n
#M  消息M，（小于N）
#
#{密文}
#
#=============================================================================================
proc rsa_enc {e n M} {

    #对输入参数进行检查
    set eByteLen [string length $e]
    if {($eByteLen % 2) || ($eByteLen == 0)} {
        return -code error {Error(rsa_enc): [rsa_enc e n M] The length of arg e should be even and not be 0.}
    }

    set nByteLen [string length $n]
    if {($nByteLen % 2) || ($nByteLen == 0)} {
        return -code error {Error(rsa_enc): [rsa_enc e n M] The length of arg n should be even and not be 0.}
    }

    set MByteLen [string length $M]
    if {($MByteLen % 2) || ($MByteLen == 0)} {
        return -code error {Error(rsa_enc): [rsa_enc e n M] The length of arg M should be even and not be 0.}
    }

    set tmpM 0x$M
    set tmpN 0x$n
    if {$tmpM >= $tmpN} {
        return -code error {Error(rsa_enc): [rsa_enc e n M]  M >= n.}
    }
    
    return [modexp $M $e $n]
}


#=============================================================================================
#rsa_dec
#
#RSA解密或验签
#
#d  私钥d
#n  模数n
#M  消息M，（小于n）
#
#{明文}
#
#=============================================================================================
proc rsa_dec {d n C} {

    #对输入参数进行检查
    set dByteLen [string length $d]
    if {($dByteLen % 2) || ($dByteLen == 0)} {
        return -code error {Error(rsa_dec): [rsa_dec d n C] The length of arg d should be even and not be 0.}
    }

    set nByteLen [string length $n]
    if {($nByteLen % 2) || ($nByteLen == 0)} {
        return -code error {Error(rsa_dec): [rsa_dec d n C] The length of arg n should be even and not be 0.}
    }

    set CByteLen [string length $C]
    if {($CByteLen % 2) || ($CByteLen == 0)} {
        return -code error {Error(rsa_dec): [rsa_dec d n C] The length of arg C should be even and not be 0.}
    }
    set tmpC 0x$C
    set tmpN 0x$n
    if {$tmpC >= $tmpN} {
        return -code error {Error(rsa_dec): [rsa_dec d n C]  C >= n.}
    }
    return [modexp $C $d $n]
}


#=============================================================================================
#rsa_crt
#
#RSA CRT运算
#
#p q 大素数
#dP dQ Qinv CRT参数
#C 密文
#
#{明文}
#
#=============================================================================================
proc rsa_crt {p q dP dQ Qinv C} {
    
    #对输入参数进行检查
    set pByteLen [string length $p]
    if {($pByteLen % 2) || ($pByteLen == 0)} {
        return -code error {Error(rsa_crt): [rsa_crt p q dP dQ Qinv] The length of arg p should be even and not be 0.}
    }

    set qByteLen [string length $q]
    if {($qByteLen % 2) || ($qByteLen == 0)} {
        return -code error {Error(rsa_crt): [rsa_crt p q dP dQ Qinv] The length of arg q should be even and not be 0.}
    }

    set dPByteLen [string length $dP]
    if {($dPByteLen % 2) || ($dPByteLen == 0)} {
        return -code error {Error(rsa_crt): [rsa_crt p q dP dQ Qinv] The length of arg dP should be even and not be 0.}
    }

    set dQByteLen [string length $dQ]
    if {($dQByteLen % 2) || ($dQByteLen == 0)} {
        return -code error {Error(rsa_crt): [rsa_crt p q dP dQ Qinv] The length of arg dQ should be even and not be 0.}
    }

    set QiByteLen [string length $Qinv]
    if {($QiByteLen % 2) || ($QiByteLen == 0)} {
        return -code error {Error(rsa_crt): [rsa_crt p q dP dQ Qinv] The length of arg Qinv should be even and not be 0.}
    }
    set CByteLen [string length $C]
    if {($CByteLen % 2) || ($CByteLen == 0)} {
        return -code error {Error(rsa_crt): [rsa_crt p q dP dQ Qinv] The length of arg C should be even and not be 0.}
    }

    #测试p，q是否为素数
    set ret [isprime $p]
    if {$ret != 01} {
        return -code error {Error(rsa_crt): [rsa_crt p q dP dQ Qinv] The arg p should be prime.}
    }
    set ret [isprime $q]
    if {$ret != 01} {
        return -code error {Error(rsa_crt): [rsa_crt p q dP dQ Qinv] The arg q should be prime.}
    }

    #模数N
    set N [mul $p $q]

    set tmpC 0x$C
    set tmpN 0x$N
    if {$tmpC >= $tmpN} {
        return -code error {Error(rsa_crt): [rsa_crt p q dP dQ Qinv] C >= p*q.}
    }

    set C1 [rem $C $p]
    set C2 [rem $C $q]
    set M1 [modexp $C1 $dP $p]
    set M2 [modexp $C2 $dQ $q]
    
    set ret [modsub $M1 $M2 $p]
    set ret [modmul $ret $Qinv $p]
    set ret [mul $ret $q]
    set ret [add $M2 $ret]

    return  $ret

}

puts "load rsa successfully!"
