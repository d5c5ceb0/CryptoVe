#===============================================================================
# pk test case for TCL
#
# pk test
#
# Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
# functions:
# test_rsa
# test_sm2
# test_ecc
# test_pkcs1
#===============================================================================
#

source [file join [file dirname [info script]] ../cryptove.tcl]

proc test_rsa {} {
	set rsa_klen 256
	for {set j 64} {$j<=$rsa_klen} {incr j 2} {

		for {set i 0} {$i < 100} {incr i 1} {

			set rsa_cklen [expr 8*$j]
			#puts rsa_${rsa_cklen}_enc_$i
			set key [rsa_keygen 010001 $j]
			set e [lindex $key 0]
			set n [lindex $key 1]
			set d [lindex $key 2]
			set p [lindex $key 3]
			set q [lindex $key 4]
			set dp [lindex $key 5]
			set dq [lindex $key 6]
			set qinv [lindex $key 7]

			set M 00[rand [expr $j-1] 0 255]
			set C [rsa_enc $e $n $M]
			set M1 [rsa_dec $d $n $C]
			set M2 [rsa_crt $p $q $dp $dq $qinv $C]

			set tmpm 0x$M
			set tmpm1 0x$M1
			set tmpm2 0x$M2
			if {$tmpm != $tmpm1} {
				puts $e
				puts $n
				puts $d
				puts $M
				puts $C
				puts $M1
				puts "rsa enc dec error 1"
				return
			}

			if {$tmpm != $tmpm2} {
				puts $e
				puts $p
				puts $q
				puts $dp
				puts $dq
				puts $qinv
				puts $M
				puts $C
				puts $M2
				puts "rsa enc dec error 2"
				return
			}
		}
	
	puts "rsa nlen=$j successfully"
	}
}


proc test_sm2 {} {
#=======================================================================================
##Z值和E值测试
#=======================================================================================
#
#公钥
set SM2_pubkey 26EA8A3930208EFD9132F71C510AAB57438B3DBC27D304E798ECCAF2A0EA74EB7500D9CFF30E631015C773728E8C2509380A22E1E742B6ABA09DCF857C42CCEA
#用户IDa
set ID 1E
#IDa字节长度
set IDlen 1 
#用户明文M
set M 6D65737361676520646967657374
#计算Za=H256(ENTLa||IDa||a||b||Xg||Yg||Xa||Ya) = F13C4E7998FD743DA0FD887540E803F85A4286241391CA6659CB168B572DE0B1
set stdZ 0xF13C4E7998FD743DA0FD887540E803F85A4286241391CA6659CB168B572DE0B1
set Z [sm2_getz $ID $SM2_pubkey]
set Z1 0x$Z
if {$Z1 != $stdZ} {
    puts "error Z"
}

#计算e=H256(Za||M) = FD780E1B1248655747C7842DBA95B76BE87D42037DD3AF9B001AC8F4376C4090
set stdE 0xFD780E1B1248655747C7842DBA95B76BE87D42037DD3AF9B001AC8F4376C4090
set E 0x[sm2_gete $Z $M]
puts $E
if {$E != $stdE} {
    puts "error E"
}

#========================================================================================
#SM2 签名 & 验签测试
#========================================================================================
#功能测试
#
set Random A8D1A8EB9ED870073D5A75E3D85BA56ED7E8A034F618DD19A5A13E36AA392032 
set dA D84DC07A8426395E0CE43AEA82DB9ACCF2568D0F2D63772D9897D1334D1F20C3	
set Pubkey CD459EA427E560E014F420F502055A20471AAE6B97CD5B66F01D87BAB250138B41DA65A7C7058F965EF911D6F5E45B536626DDE93E687C085EB506DC94BEDF79
set Ehash 7C84316FC719431CA7921ACED955B407600C880F97D21826F438358051D0CB21

set sig_r 53572E8EE06A2DC311ED8A6087E6A0E71C8C42E360B10B55983397964F44ECFF
set sig_s 3538D6F877B83AB3C9E298BBA7459C9629B533281A5A823EAC601DE8CFF5A0CB
#
set RS [sm2_sig $Random $dA $Ehash]
puts $RS
set tmpRS ${sig_r}${sig_s}
if {$RS != $tmpRS} {
    puts "error"
    return
}
set ret [sm2_ver $Pubkey $RS $Ehash]
if {$ret != 0} {
    puts "error"
    return
}

#
#正确性测试
#
set SM2_SigVerTimes 100
for {set i 0} {$i < $SM2_SigVerTimes} {incr i 1} {

    puts sigver_$i

    set Ehash [rand 0x20 0 255]
    set key [sm2_keygen]
	#puts [string length $key]
    set prikey [lindex $key 0]
    set pubkey [lindex $key 1]

    set random [rand 0x20 0 255]
    set RS [sm2_sig $random $prikey $Ehash]
#    puts $RS
	#puts $pubkey
    set ret [sm2_ver $pubkey $RS $Ehash]
#    puts $ret

    if {$ret != 0} {
        puts "sign verify error"
        return
    }
}
puts "sigver end!"

##=============================================================================================
#SM2 密钥交换测试
#==============================================================================================
#
#@1 功能测试

#参数P
set sm2_p 8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
#参数A
set sm2_a 787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
#参数B
set sm2_b 63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
#参数N
set sm2_n 8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
#参数Xg
set sm2_gx 421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
#参数Yg
set sm2_gy 0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
#参数h
set sm2_h 00000001

#用户A的私钥dA：
set dA 6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE
#用户A的公钥PA：
set PA 3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE16553DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B
#用户B的私钥dB：
set dB 5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53
#用户B的公钥PB：
set PB 245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F4353C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C
#杂凑值ZA=H256(ENTLA||IDA||a||b||xG||yG||xA||yA)。
set ZA E4D1D0C3CA4C7F11BC8FF8CB3F4C02A78F108FA098E51A668487240F75E20F31
#杂凑值ZB=H256(ENTLB||IDB||a||b||xG||yG||xB||yB)。
set ZB 6B4B6D0E276691BD4A11BF72F4FB501AE309FDACB72FA6CC336E6656119ABD67

#临时私钥rA：
set rdA 83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563
#计算椭圆曲线点RA=[rA]G=(x1,y1)：
set rPA 6CB5633816F4DD560B1DEC458310CBCC6856C09505324A6D23150C408F162BF00D6FCF62F1036C0A1B6DACCF57399223A65F7D7BF2D9637E5BBBEB857961BF1A
#临时私钥rB：
set rdB 33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80
#计算椭圆曲线点RB=[rB]G=(x2,y2)：
set rPB 1799B2A2C778295300D9A2325C686129B8F2B5337B3DCF4514E8BBC19D900EE554C9288C82733EFDF7808AE7F27D0E732F7C73A7D9AC98B7D8740A91D0DB3CF4

#标准结果:
#key: 55b0ac62a6b927ba23703832c853ded4
#s1 sb: 284C8F198F141B502E81250F1581C7E9EEB4CA6990F9E02DF388B45471F5BC5C
#s2 sa: 23444DAF8ED7534366CB901C84B3BDBB63504F4065C1116C91A4C00697E6CF7A
#puts [sm2_kex 0 16 $ZA $ZB ${dA}${PA} ${rdA}${rPA} $PB $rPB]


#
#@2 正确性
#
#
set SM2_ExKey_Times 100
for {set j 0} {$j < $SM2_ExKey_Times} {incr j 1} {

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


    puts exkey_$j

    set IDA 048831f0a5e800bfaae7
    set IDB 74aba8e7290ee5b65b5a 

    set Prikey_A 428334ce812514d80cb3a2756f193f1d7e1a36d6e67f3142d92b0ec15f7bd263 
    set Pubkey_A 170ab0645b325ba969df89c3be73101b2f22886baea24ac24d3bec1ffefc48c82106ec3d2f02984945920f8fc980db75169777203d47782e5d2b0269ccbe5d5d

    set Prikey_B 1674a6e07f92b9ddb286d8df1766a67ef22e1c4168b472c4d181ff722c6165b8
    set Pubkey_B 5b5c0df14e591f75465177c093de669dfd4af5b8859274c0149c0a6e3c577908a1e55cde9a563404c5932ab790ee530a22a5622e3de855a58950b3dd89f4b5a6
    #ZA  AFDEE10FCCD42B5D9F84B3C5B9EEA3E9BE98CB1E82A6746EA08D0ACB84DEC6C9
    #ZB  F99E09A596BCA1CEF1EE92E1197C3A3C9756529A7AAEE5FB84120275C81ACE2D

    #发起方A
    set Za [sm2_getz $IDA $Pubkey_A]
    set TA [sm2_keygen]
    set RA [lindex $TA 0][lindex $TA 1]

    #接收方B
    set Zb [sm2_getz $IDB $Pubkey_B]
    set TB [sm2_keygen]
    set RB [lindex $TB 0][lindex $TB 1]
    
    #set rKA 10c6bc06188275dc9260aa1e14d049a001bd17514911a2517c42a12418597b385f83cc520446010622dfdbcfbdc5903d799020a26d70d0f32850d3bbf58dc131632dcf3726d231c28f835f811f0193fce174a631e0b3f02cff16d0bf8fc4f6bd

    #set rKB cc2b415ba7e93a404b49eb1021f087a562fadb7b0e149aede1acede351b17fa8b1ea1ecceb714f6fcd45f17946aeb77f8b951b40dd024bcd2ff4a741b34d6ddd03a65e37e33c9ac21af627a1c7f19e60c95ffb9a92f1037bcd9491a1c7fe8bb9

    #发起方A
    set oKA [sm2_kex 0 100 $Za $Zb ${Prikey_A}${Pubkey_A} ${RA} $Pubkey_B [string range $RB 64 191]]

    #接收方B
    set oKB [sm2_kex 1 100 $Zb $Za ${Prikey_B}${Pubkey_B} ${RB} $Pubkey_A [string range $RA 64 191]]

    set retA 0x[lindex $oKA 0]
    set retB 0x[lindex $oKB 0]

    if {$retA != $retB} {
        puts $oKA
        puts $oKB
        puts "error 2"
        return
    }

    set retA 0x[lindex $oKA 1]
    set retB 0x[lindex $oKB 1]

    if {$retA != $retB} {
        puts $oKA
        puts $oKB
        puts "error 3"
        return
    }

    set retA 0x[lindex $oKA 2]
    set retB 0x[lindex $oKB 2]

    if {$retA != $retB} {
        puts $oKA
        puts $oKB
        puts "error 4"
        return
    }
}

puts "extkey end!"
	#==============================================================================================
	#加解密
	#==============================================================================================
	#测试数据
	set sRandom C9FFCE9C0FDFCD9962C5BF9CF5891F881531760D7D45E2D2E5E54A4006499243
	set sM2_PriKey 700BE499A4EFE27A8369F58BFFE0F5563CDFF772E11832254DDE10E324A81755
	set sM2_PubKey BC4EADB005F9AADF6BB8573DE5C430A12B023A2471402813CB4D066FC3D681648F98951D3EE032E6F4A4AB2B79510D5721767492E94F31B82C1603731E6CB92A
	set sM2_sM ce8f1ce36e5e62b16772
	set sM2_sC E594A5745BBBD5539D68711C64CA55898A284C9081B65CA36E388062045A357C97AEFE68641FAB6E6A3E4E10855C7C3DE9B8F9417381E4FBB020E9303926BC77126D6F6F74993DD43233C284A0840040EF2E77B0383B9EF5F73B1803DB7F4503C66D9F3544BCB59239D5

	set C [sm2_enc $sRandom $sM2_PubKey $sM2_sM]
	puts $C

	set M [sm2_dec $sM2_PriKey $C]
	puts $M


	set sRandom 0B7F12249F3EB7EB7E341D8B635F4DA4C28BCF4E3B4ED76EB94C8AD9FAF4F1C5
	set sM2_PriKey 00F57B6E444A7AC0673CA51BB27D078ACC62FF066A7DB4542A1222CF2AEBC171
	set sM2_PubKey 70CC7EB501B3CDE5AA7A0866613E23C02D3544F1889DBCDB872553435E0012180FAE376CC449788D8510BD768B6D1FD401222FB06271485A7BF97911F851EF3B
	set sM2_sM 344d5fede931fd95982f9f3db66e49c3c1bb70dad325aec5b2b506a6092f52aefaaffc208abf9c84c851afbba57a9358285e041442604943be86f4f47720d6aa1b60f789d9c0a6af23368f67bba1f6d75e5b8cba840cbf7130c1e28cf50b48e78b308c87
	set sM2_sC 4D561120484EA5211495CCC0A49DA9FC232453643C2619FF83AC08D710D9BC25724FF5E5E368AFB896C4A7A15A1A5396CB5D6CD98B9E4C55D430778B816FBA546623D529EB1656EA34506FFE4AB2D597E30FC7D26ABC48B1CBC8B97BCB28BD7D47BC44EFDE1307596EEDDF5C212502F50EA2C0A2FE3F41B8E97F816EE8F91469F7F7F18EA572E562D8B9212E65406B5ACB370490AB33F636287FEF4EA248D6C2379ED09162F55990F43439E06F9BE1E1D60908727B1E6064D8858446C9DC22191F028A55

	set C [sm2_enc $sRandom $sM2_PubKey $sM2_sM]
	puts $C

	set M [sm2_dec $sM2_PriKey $C]
	puts $M



	set SM2_EncDecTimes 100
	for {set i 1} {$i <= $SM2_EncDecTimes} {incr i 1} {

		puts encdec_$i

		#密钥生成
		set key [sm2_keygen]
		set prikey [lindex $key 0]
		set pubkey [lindex $key 1]

		set random [rand 0x20 0 255]

		#加密
		set M [rand $i 0 255]
		set C [sm2_enc $random $pubkey $M]
		#解密
		set ret [sm2_dec $prikey $C]

		if {$ret != $M} {
			puts "enc dec error"
			return
		}
	}
	puts "encdec end!"
}

proc test_ecc {} {

}



proc test_pkcs1 {} {
}
