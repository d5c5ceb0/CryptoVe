#===============================================================================
#DES算法Tcl实现
#
#实现了DES加解密功能，包括DES ECB模式加解密、3DES 2-keyECB模式加解密、 
#3DES 3-key ECB模式加解密
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#函数介绍
#1. desecb  DES ECB模式加解密                   desecb mode key data
#2. tdesecb 3DES ECB模式加解密(2-key, 3-key)    tdesecb mode key data
#===============================================================================

package provide crypto 1.0.0

load [file join [file dirname [info script]] ../lib/libcrypto[info sharedlibextension]]

#desecb  in libcrypto library
#
#
#tdesecb
#ECB模式的3DES命令
#mode 加解密选择， 00-加密，01-解密
#key  密钥，16或24字节
#data 输入数据，8字节倍数
proc tdesecb {mode key data} {
    
    #判断mode是否符合要求
    if {($mode != 00) && ($mode != 01)} {
        return -code error {Error(tdesecb):[tdesecb mode key data] The arg mode should be 00 or 01.}
    }

    #判断key是否符合要求
    set klen [string length $key]
    if {($klen != 8*2*2) && ($klen != 8*3*2)} {
        return -code error {Error(tdesecb):[tdesecb mode key data] The length of arg key should be 16 bytes or 24 bytes.}
    }

    #判断data是否符合要求
    set dlen [string length $data]
    if {$dlen % (8*2)} {
        return -code error {Error(tdesecb):[tdesecb mode key data] The length of arg data should be multiple of 8 bytes.}
    }

    if {$klen == 8*2*2} {
        set tkey1 [string range $key 0 15]
        set tkey2 [string range $key 16 31]
        set tkey3 $tkey1
    } else { 
        set tkey1 [string range $key 0 15]
        set tkey2 [string range $key 16 31]
        set tkey3 [string range $key 32 47]
    }

    set out ""

    #00加密，01解密
    if {$mode == 00} {
        for {set i 0} {$i < $dlen/(8*2)} {incr i 1} {
            set tmpm [string range $data [expr $i*8*2] [expr $i*8*2+15]]   
            set tmpm [desecb 00 $tkey1 $tmpm]
            set tmpm [desecb 01 $tkey2 $tmpm]
            set tmpm [desecb 00 $tkey3 $tmpm]
            append out $tmpm
        }

    } else {
        for {set i 0} {$i < $dlen/(8*2)} {incr i 1} {
            set tmpm [string range $data [expr $i*8*2] [expr $i*8*2+15]]   
            set tmpm [desecb 01 $tkey3 $tmpm]
            set tmpm [desecb 00 $tkey2 $tmpm]
            set tmpm [desecb 01 $tkey1 $tmpm]
            append out $tmpm
        }

    }

    return $out

}
