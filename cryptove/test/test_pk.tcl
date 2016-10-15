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


set RSA_LOOP_TIMES 1

proc test_rsa {} {
	global RSA_LOOP_TIMES
	set rsa_klen 256
	for {set j 64} {$j<=$rsa_klen} {incr j 2} {

		for {set i 0} {$i < $RSA_LOOP_TIMES} {incr i 1} {

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

set ecc_test_data {
	secp160k1 {
		prikey    202158741ABE6B5BCB9BF5648D8288A11343ABE2
		pubkey    1161706E49EE70E33A8C62C449ED098AB8CA93D3E6205A1AE3F9D37A5FCA463C644B55A4F9C29244
		signature F311960D0A6FEC9E324F7FF162C1AB273C234D0CF24F420D3A08C2529E2C9FD97B70E553ED15F9A7
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
	secp160r1 {
		prikey    202158741ABE6B5BCB9BF5648D8288A11343ABE2
		pubkey    78BB18FE051B7B6AAFBDF8EFAF12C0A566C38390469EA0D821485E40A715F19B8EAD1534B97356B4
		signature 236DC0F04D1E32D2FAC93E83F7A27D0B4EAE3A243869D858E201AF3AD15E520EE8F901E86E90759D
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
	secp160r2 {
		prikey    202158741ABE6B5BCB9BF5648D8288A11343ABE2
		pubkey    7B851F2EE675F9B9B74649DFD1B55CB47E8CA2A93B6D475028871176D2203407088077A428CC9270
		signature DB3626402745F8415F9C179C532ADD209DF47FF434BF4B196BACB58AA22B4BBC849E5B0F57B5AB67
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
	secp192k1 {
		prikey    202158741ABE6B5BCB9BF5648D8288A1E5318D5E1343ABE2
		pubkey    FDA8AC008FBEFE33A0AD17D2755DAFD1B53265125F95A66ABB7B06575CFC177C66AF68F09FBE6127A707E4A1AD78B03F
		signature 9D0F46AD0AB8A3AF9F7CDFBB371D11DA32918AB083C36B6AE943FFD125C728A325CECA9A36479FFE9D9E4C13061D22DC
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
	secp192r1 {
		prikey    202158741ABE6B5BCB9BF5648D8288A1E5318D5E1343ABE2
		pubkey    F302235F15B8C4B7A2C646B0BBA426D985BFBF0A749873E8971B5A676FFE80F1DAC1FB4CA7102B460A6E791ED950D4EC
		signature BB124CA203400840506A4A3078360A954B3DBFC461176DC7DF63F69CC442B49D4747AE55FF2013191ECCC05B929EAA53
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
	secp224k1 {
		prikey    5d49b3d21766bb40bbb7dc30a879ba9e4384e8ae7f65b9710b33e3de
		pubkey    440BBFFDB176B6F829D207CA2983C7BB44746F10F31374CC75529487ABE68E35865BB285FF387E4983B54082527C69EED875AF4D25B21253
		signature F2A29C3ACD984C942B0D9958E902CD0A4BB3BDA3FAC199EF6865F5C25C409E0D1E13950F22519836FD58128015D41D700FAB692DC9BD8E58
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
	secp224r1 {
		prikey    5d49b3d21766bb40bbb7dc30a879ba9e4384e8ae7f65b9710b33e3de
		pubkey    e001c6b5be3874d5ee8d114a356c948ed6c4329a48c1b5e58be83c53c47e3dee35de593e2ea94c757bd91701e892b1f185190b364e852ef1
		signature a529b7786b6dceecaf38cf2abeb5d6e695c8f9a63329fa00d4c195b6e9def5561a6039a94f45d60354d7272f4900835c439603d98108631c
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
	secp256k1 {
		prikey    3449ff64bc7e1e67f7d5e26e8574cf5ead005675f1324537426d4aa7f4d4bf0f
		pubkey    23D23D2F0227E45FAB5F1528A3522450E501894375B7E854EB26740A8901E949B81BB726B5C234E3FD0F293ACD2F3D094F3940D05E7B1008F2178C6489806413
		signature 3B1263550B017E64A061F7A8E6C0B52E5AD219CE261D669A9B06A5C875EC986E4D1DF341D1E4144BE7396B911A9946089D37BCAC8D1E17E41646DAAA5A582C19
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
	secp256r1 {
		prikey    595b41ddb284b6ad945f3845f29b3cf05fc1446b44573760723528c19b318663
		pubkey    bab4b4074649a187d429369d879752c9bdb14ba92cefd775aa36cb7661748b4f03a35ef901c8954e20f02d46652058c6e306494773b2f1a4220acb1f2b3865e6
		signature 5b066e018db90c071e321b0959e9420a960eec5b86392b2fc0ea0610d60de8bd45e6f16b77999b64bb71bf7d9c21f6cc7bcf0c73c78063b07a43d2607611e896
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
	secp384r1 {
		prikey    1644afdb5ddde5090eb1e427fd57f5672ce33f18e82faf71da036975263efc3fcff6764703c70e25f845b40f50359cf7
		pubkey    65b44a89c45b95a75c28259e054bd01e03d1a419947c3c9c980f109df5f636516a8d1607f1825c6063b751d4ec03da28be862583362b9fb13b6e6b11aa239bcc8f3e688968f30103bbd231f397ff4af3252be82ac0a32dc4847067854c30798f
		signature 4e5853680efaa1dd9eee051607ad324724cb6122b37941a0f94b853cd53deec5728afbd1af6c0d60985069384efacd73e7c1646f080419bc8bd05d357e419d2374e22e25887e0a159b9ed908b9e332b4d463bc9a6d4fd3c70557464571b2f36c
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
	secp521r1 {
		prikey    000001c1964a8683a308751c9f0653e5fb2aba8476643f5078b5af7798b937043ec6ed3ced86969b6bea4d411de0b844766f6a2e6787e47831918a30ae66f518fbd854a7
		pubkey    0000002a9d94a9fe2661893d486be9ccb1df1ebf6f11d0ccf9469078621a046c1f8311403068717df3eace0f25505633189943ac4bbbd9227d8d53850a050048a01b49350000003f1e7334c78ff65c0e873eb8fcdeb04394c5af6979d44866ded4a3074c284c7be3a7c729778f9c270cf58ea4a69ae7e662c80fc8c920c0f57b1087c683f116cce7
		signature 00000142700dfcd62fb7e3eef70a4ee5d27cdad47cd05fc21d52e6f50602b0fa9b0cb0cf1aa702b274a52d87c7c39b0a971887b9fca8bbbafcd8d07e507d37bd0d1bd38a000001be42328c10b30dce0eadaab2e6d2fd5ee293bd7c2dcf6c59baf5df4cb28a93244491621b810d30132f6275a447b216f19ed54b9a1fb8652a5c68ac3381e2874203
		mhash     a9993e364706816aba3e25717850c26c9cd0d89d
	}
}

proc ecdsa_test_once {curve times} {
	global ecc_test_data
	set prikey     [dict get [dict get $ecc_test_data $curve] prikey]
	set pubkey     [dict get [dict get $ecc_test_data $curve] pubkey]
	set signature  [dict get [dict get $ecc_test_data $curve] signature]
	set mhash      [dict get [dict get $ecc_test_data $curve] mhash]

	#verify
	set res [ecc_verify $curve $pubkey $signature $mhash]
	puts $res
	if {$res != 0} {
		puts $res
		return -code error "ecc_verify $curve error!"
	}
	puts "ecc_verify $curve success"
	#sign
	set sklen [expr [string length $prikey]/2]
	for {set i 0} {$i < $times} {incr i } {
		set random 00000000[rand [expr $sklen-4] 0 256]
		set RS [ecc_sign $curve $random $prikey $mhash]
		puts $RS
		set R [lindex $RS 0]
		set S [lindex $RS 1]
		puts $R
		puts $S
		set res [ecc_verify $curve $pubkey ${R}${S} $mhash]
		puts $res
		if {$res != 0} {
			puts $res
			return -code error "ecc_sign $curve error!"
		}
	}
	puts "ecc_sign $curve success"
}

proc ecdsa_test {times} {

	#secp160k1
	ecdsa_test_once secp160k1 $times
	#secp160r1
	ecdsa_test_once secp160r1 $times
	#secp160r2
	ecdsa_test_once secp160r2 $times
	#secp192k1
	ecdsa_test_once secp192k1 $times
	#secp192r1
	ecdsa_test_once secp192r1 $times
	#secp224k1
	ecdsa_test_once secp224k1 $times
	#secp224r1
	ecdsa_test_once secp224r1 $times
	#secp256k1
	ecdsa_test_once secp256k1 $times
	#secp256r1
	ecdsa_test_once secp256r1 $times
	#secp384r1
	ecdsa_test_once secp384r1 $times
	#secp521r1
	ecdsa_test_once secp521r1 $times
}

proc eckeygen_test_once {curve times} {
	global ecc_test_data

	set mhash      [dict get [dict get $ecc_test_data $curve] mhash]

	for {set i 0} {$i < $times} {incr i} {
		set ec_key [ecc_keygen $curve]
		puts $ec_key
		set prikey [lindex $ec_key 0]
		set pubkey [lindex $ec_key 1]

		#get pubkey from prikey
		set tempkey [ecc_keygen_sk $curve $prikey]	
		if {[cmp $tempkey $pubkey]} {
			puts gen_$tempkey
			puts std_$pubkey
			return -code error "ecc_keygen_sk $curve error!"
		}

		#sign
		set sklen [expr [string length $prikey]/2]
		set random 00000000[rand [expr $sklen-4] 0 256]
		set RS [ecc_sign $curve $random $prikey $mhash]
		puts $RS
		set R [lindex $RS 0]
		set S [lindex $RS 1]
		puts $R
		puts $S
		#verify
		set res [ecc_verify $curve $pubkey ${R}${S} $mhash]
		puts $res
		if {$res != 0} {
			puts $res
			return -code error "ecc_keygen $curve error!"
		}
	}
	puts "ecc_keygen $curve success"
}


proc eckeygen_test {times} {
	#secp160k1
	eckeygen_test_once secp160k1 $times
	#secp160r1
	eckeygen_test_once secp160r1 $times
	#secp160r2
	eckeygen_test_once secp160r2 $times
	#secp192k1
	eckeygen_test_once secp192k1 $times
	#secp192r1
	eckeygen_test_once secp192r1 $times
	#secp224k1
	eckeygen_test_once secp224k1 $times
	#secp224r1
	eckeygen_test_once secp224r1 $times
	#secp256k1
	eckeygen_test_once secp256k1 $times
	#secp256r1
	eckeygen_test_once secp256r1 $times
	#secp384r1
	eckeygen_test_once secp384r1 $times
	#secp521r1
	eckeygen_test_once secp521r1 $times
}

proc ecdh_test_once {curve times} {
	global ecc_curve_list
	global ecc_test_data

	set prikey     [dict get [dict get $ecc_test_data $curve] prikey]
	set pubkey     [dict get [dict get $ecc_test_data $curve] pubkey]

	set gx [dict get [dict get $ecc_curve_list $curve] ecc_gx]
	set gy [dict get [dict get $ecc_curve_list $curve] ecc_gy]

	set xlen [expr [string length $gx]/2]

	set pubkx   [ecc_dh $curve $prikey ${gx}${gy}]
	set pubkeyx [string range $pubkey 0 [expr $xlen*2-1]]
	puts $pubkx
	puts $pubkeyx

	if {[cmp $pubkx $pubkeyx]} {
		puts $pubkx
		puts $pubkeyx
		return -code error "ecc_dh $curve test fail"
	}
	
	for {set i 0} {$i < $times} {incr i} {
		set keyA [ecc_keygen $curve]
		set prikeyA [lindex $keyA 0]
		set pubkeyA [lindex $keyA 1]

		set keyB [ecc_keygen $curve]
		set prikeyB [lindex $keyB 0]
		set pubkeyB [lindex $keyB 1]

		set sharedKeyA [ecc_dh $curve $prikeyA $pubkeyB]
		set sharedKeyB [ecc_dh $curve $prikeyB $pubkeyA]
		puts $sharedKeyA
		puts $sharedKeyB
		if {[cmp $sharedKeyA $sharedKeyB]} {
			puts $sharedKeyA
			puts $sharedKeyB
			return -code error "ecc_dh $curve loop test fail"
		}
	}

	puts "ecc_dh $curve test pass"
}

proc ecdh_test {times} {
	#secp160k1
	ecdh_test_once secp160k1 $times
	#secp160r1
	ecdh_test_once secp160r1 $times
	#secp160r2
	ecdh_test_once secp160r2 $times
	#secp192k1
	ecdh_test_once secp192k1 $times
	#secp192r1
	ecdh_test_once secp192r1 $times
	#secp224k1
	ecdh_test_once secp224k1 $times
	#secp224r1
	ecdh_test_once secp224r1 $times
	#secp256k1
	ecdh_test_once secp256k1 $times
	#secp256r1
	ecdh_test_once secp256r1 $times
	#secp384r1
	ecdh_test_once secp384r1 $times
	#secp521r1
	ecdh_test_once secp521r1 $times
}


set ECC_LOOP_TIMES 1
proc test_ecc {{algo ALL}} {
	global ECC_LOOP_TIMES
	switch $algo {
		"ECDSA" { 
			ecdsa_test $ECC_LOOP_TIMES
		}
		"KEYGEN" {
			eckeygen_test $ECC_LOOP_TIMES
		}
		"ECDH"  {
			ecdh_test $ECC_LOOP_TIMES
		}
		"ALL" {
			ecdsa_test $ECC_LOOP_TIMES
			eckeygen_test $ECC_LOOP_TIMES
			ecdh_test $ECC_LOOP_TIMES
		}
	}
}


proc test_pkcs1 {} {
	set n a0f855d8194eb182cd8f435805ce75524b2c7fdfdb2d7a82a5288112a42ebb5decf87648d09131f4ad38e7a31d028c69ca5c8516792e2bf3477a1a7e9813efd4d11996bbe56195f40e06036a27e902137c7e80dddb0e2856b722e302c9d21df3ed30dfa8fb849c8c86ae9d71fdea7d47f8535b34b381b33c4b1e4d0095807a5d628fc01984d28d7427712a16e3cf871bfc5cf901865067e2d5847d32822c75b4bc94abb2f0e624918af766bbd8a1c60691445f810748f766ac1105db97335cc0a6802e08800e2e7ef8a04bad3e1e3f90525d08a9a4f2e40f7f32a0646861b531662b3af7026b82e35588891e063bc171ba242e6bbb6873fece2f1e85d92e0d1b
	set d  9a076765643a07e3e93cf82ce7497abc2750ca7ff363de41db3619e43394c0178d64e7129ff8ffbb6871f63cffca6b7fe3728aab4983a3eca3edb42284f536de06c41c976953eac06116e1f7977f004c93291db8ad1f2bfc663b8ccc2340db068965e5eef5d61c52dfa180e90e166e910a8f00cc3a2496d4cff08bb04e5e653727bcdc788c24c5041cc0713c6b51cee6f2b82abc223d252746f5a373d94b1803d2740049312fb96c64260aa7eeec95e29e7cafd00975544de5502044069753c9573919cd2d92880f50bd2e368bad093ed060bbed6825c2c3abf4d82a934138b000028ecadf7ab15a02be5a90200ca6e40628ad1b10214571d405ec7ba6969321
	set e 010001
	set msg ec174729c4f5c570ba0de4c424cdcbf0362a7718039464

	set s 17e483781695067a25bc7cb204429a8754af36032038460e1938c28cd058025b14d2cffe5d3da39e766542014e5419f1d4c4d7d8e3ebcd2221dde04d24bbbad657f6782b7a0fada3c3ea595bc21054b0abd1eb1ada86276ed31dbcce58be7407cbbb924d595fbf44f2bb6e3eab92296076e291439107e67912b4fac3a27ff84af7cd2db1385a8340b2e49c7c2ec96a6b657a1641da80799cb88734cca35a2b3a2c4af832a34ac8d3134ccc8b61150dc1b64391888a3a84bdb5184b48e8509e8ba726ba8847e4ca0640ce615e3adf5248ce08adb6484f6f29caf6c65308ec6351d97369ae005a7c762f76f0ddc0becc3e45529aa9c8391473e392c9a60c2d0834
	set salt 0102
	if {[rsa_verify_pss sha1 $e $n $s $msg] != 00} {
		return -code error "rsa_verify_pss error"
	}
	puts "pkcs1 rsa_verify_pss pass"
    set s [rsa_sign_pss sha1 $d $n $msg $salt]
	puts s_$s
	if {[rsa_verify_pss sha1 $e $n $s $msg] != 00} {
		return -code error "rsa_sign_pss error"
	}
	puts "pkcs1 rsa_sign_pss pass"

}
