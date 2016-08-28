#===============================================================================
#crc16 for TCL
#
#crc16 api
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#函数介绍
#1.  crc16TbGen Poly 产生多形式为$Poly的半字节查找表
#2.  crc16           通用CRC-16算法
#3.  crc16Ibm        模型为CRC-16, CRC-IBM, CRC-16/ARC, CRC-16/LHA的CRC算法
#4.  crc16AugCcitt   模型为CRC-16/AUG-CCITT, CRC-16/SPI-FUJITSU的CRC算法
#5.  crc16Buypass    模型为CRC-16/BUYPASS, CRC-16/VERIFONE的CRC算法
#6.  crc16CcittFalse 模型为CRC-16/CCITT-FALSE的CRC算法
#7.  crc16Cdma2000   模型为CRC-16/CDMA2000的CRC算法
#8.  crc16Dds110     模型为CRC-16/DDS-100的CRC算法
#9.  crc16DectR      模型为CRC-16/DECT-R, R-CRC-16的CRC算法
#10. crc16DectX      模型为CRC-16/DECT-X, X-CRC-16的CRC算法
#11. crc16Dnp        模型为CRC-16/DNP的CRC算法
#12. crc16En13757    模型为CRC-16/EN-13757的CRC算法
#13. crc16Genibus    模型为CRC-16/GENIBUS, CRC-16/EPC, CRC-16/I-CODE, CRC-16/DARC的CRC算法
#14. crc16Maxim      模型为CRC-16/MAXIM的CRC算法
#15. crc16Mcrf4xx    模型为CRC-16/MCRF4XX的CRC算法
#16. crc16Riello     模型为CRC-16/RIELLO的CRC算法
#17. crc16T10Dif     模型为CRC-16/T10-DIF的CRC算法
#18. crc16Teledisk   模型为CRC-16/TELEDISK的CRC算法
#19. crc16Tms37157   模型为CRC-16/TMS37157的CRC算法
#20. crc16Usb        模型为CRC-16/USB的CRC算法
#21. crcA            模型为CRC-A的CRC算法
#22. crcB            模型为CRC-B的CRC算法
#23. crc16Ccitt      模型为CRC-16/CCITT, CRC-16/CCITT-TRUE, CRC-16/KERMIT, CRC-CCITT的CRC算法
#24. crc16Modbus     模型为MODBUS的CRC算法
#25. crc16X25        模型为X-25, CRC-16/IBM-SDLC, CRC-16/ISO-HDLC, CRC-B的CRC算法
#26. crc16Xmodem     模型为XMODEM, ZMODEM, CRC-16/ACORN的CRC算法
#===============================================================================

package provide crypto 1.0.0

#crc16 Poly 1021
set CrcTable1021(0) 0x0000; set CrcTable1021(1) 0x1021; set CrcTable1021(2) 0x2042; set CrcTable1021(3) 0x3063;
set CrcTable1021(4) 0x4084; set CrcTable1021(5) 0x50a5; set CrcTable1021(6) 0x60c6; set CrcTable1021(7) 0x70e7;
set CrcTable1021(8) 0x8108; set CrcTable1021(9) 0x9129; set CrcTable1021(10) 0xa14a; set CrcTable1021(11) 0xb16b;
set CrcTable1021(12) 0xc18c; set CrcTable1021(13) 0xd1ad; set CrcTable1021(14) 0xe1ce; set CrcTable1021(15) 0xf1ef;

#Crc Poly 8005
set CrcTable8005(0) 0x0000; set CrcTable8005(1) 0x8005; set CrcTable8005(2) 0x800f; set CrcTable8005(3) 0x000a;
set CrcTable8005(4) 0x801b; set CrcTable8005(5) 0x001e; set CrcTable8005(6) 0x0014; set CrcTable8005(7) 0x8011;
set CrcTable8005(8) 0x8033; set CrcTable8005(9) 0x0036; set CrcTable8005(10) 0x003c; set CrcTable8005(11) 0x8039;
set CrcTable8005(12) 0x0028; set CrcTable8005(13) 0x802d; set CrcTable8005(14) 0x8027; set CrcTable8005(15) 0x0022;

#Crc Poly c867
set CrcTablec867(0) 0x0000; set CrcTablec867(1) 0xc867; set CrcTablec867(2) 0x58a9; set CrcTablec867(3) 0x90ce;
set CrcTablec867(4) 0xb152; set CrcTablec867(5) 0x7935; set CrcTablec867(6) 0xe9fb; set CrcTablec867(7) 0x219c;
set CrcTablec867(8) 0xaac3; set CrcTablec867(9) 0x62a4; set CrcTablec867(10) 0xf26a; set CrcTablec867(11) 0x3a0d;
set CrcTablec867(12) 0x1b91; set CrcTablec867(13) 0xd3f6; set CrcTablec867(14) 0x4338; set CrcTablec867(15) 0x8b5f;

#Crc Poly 0589
set CrcTable0589(0) 0x0000; set CrcTable0589(1) 0x0589; set CrcTable0589(2) 0x0b12; set CrcTable0589(3) 0x0e9b;
set CrcTable0589(4) 0x1624; set CrcTable0589(5) 0x13ad; set CrcTable0589(6) 0x1d36; set CrcTable0589(7) 0x18bf;
set CrcTable0589(8) 0x2c48; set CrcTable0589(9) 0x29c1; set CrcTable0589(10) 0x275a; set CrcTable0589(11) 0x22d3;
set CrcTable0589(12) 0x3a6c; set CrcTable0589(13) 0x3fe5; set CrcTable0589(14) 0x317e; set CrcTable0589(15) 0x34f7;

#Crc Poly 3d65 
set CrcTable3d65(0) 0x0000; set CrcTable3d65(1) 0x3d65; set CrcTable3d65(2) 0x7aca; set CrcTable3d65(3) 0x47af;
set CrcTable3d65(4) 0xf594; set CrcTable3d65(5) 0xc8f1; set CrcTable3d65(6) 0x8f5e; set CrcTable3d65(7) 0xb23b;
set CrcTable3d65(8) 0xd64d; set CrcTable3d65(9) 0xeb28; set CrcTable3d65(10) 0xac87; set CrcTable3d65(11) 0x91e2;
set CrcTable3d65(12) 0x23d9; set CrcTable3d65(13) 0x1ebc; set CrcTable3d65(14) 0x5913; set CrcTable3d65(15) 0x6476;

#Crc Poly 8bb7 
set CrcTable8bb7(0) 0x0000; set CrcTable8bb7(1) 0x8bb7; set CrcTable8bb7(2) 0x9cd9; set CrcTable8bb7(3) 0x176e;
set CrcTable8bb7(4) 0xb205; set CrcTable8bb7(5) 0x39b2; set CrcTable8bb7(6) 0x2edc; set CrcTable8bb7(7) 0xa56b;
set CrcTable8bb7(8) 0xefbd; set CrcTable8bb7(9) 0x640a; set CrcTable8bb7(10) 0x7364; set CrcTable8bb7(11) 0xf8d3;
set CrcTable8bb7(12) 0x5db8; set CrcTable8bb7(13) 0xd60f; set CrcTable8bb7(14) 0xc161; set CrcTable8bb7(15) 0x4ad6;

#Crc Poly a097
set CrcTablea097(0) 0x0000; set CrcTablea097(1) 0xa097; set CrcTablea097(2) 0xe1b9; set CrcTablea097(3) 0x412e;
set CrcTablea097(4) 0x63e5; set CrcTablea097(5) 0xc372; set CrcTablea097(6) 0x825c; set CrcTablea097(7) 0x22cb;
set CrcTablea097(8) 0xc7ca; set CrcTablea097(9) 0x675d; set CrcTablea097(10) 0x2673; set CrcTablea097(11) 0x86e4;
set CrcTablea097(12) 0xa42f; set CrcTablea097(13) 0x04b8; set CrcTablea097(14) 0x4596; set CrcTablea097(15) 0xe501;
#################################################################################################################### 
# 产生半字节查询表函数
####################################################################################################################
proc crc16TbGen {Poly} {
    
    for {set i 0} {$i < 16} {incr i 1} {
        set CrcReg 0
        for {set j 0x80} {$j != 0} {set j [expr $j/2]} {
            if {($CrcReg & 0x8000) != 0} {
                set CrcReg [expr $CrcReg * 2 & 0xFFFF]
                set CrcReg [expr $CrcReg ^ 0x$Poly]
            } else {
                set CrcReg [expr $CrcReg * 2 & 0xFFFF]
            }
            if {($i & $j) != 0} {
                set CrcReg [expr $CrcReg ^ 0x$Poly]
            }
        }
        puts [format %04x $CrcReg]
    }
}

#####################################################################################################################
#镜像函数
#####################################################################################################################
proc CrcReflect {Num BitLen} {
    
    set  Result 0
    for {set i 0} {$i < $BitLen} {incr i 1} {
        set Result [expr $Result * 2 + ($Num >> $i & 0x01)]
    }

    return $Result
}

######################################################################################################################
#CRC 16 基本计算函数
######################################################################################################################
proc crc16 {Poly Init RefIn RefOut XorOut Data} {
    global CrcTable1021
    global CrcTable8005
    global CrcTablec867
    global CrcTable0589
    global CrcTable3d65
    global CrcTable8bb7
    global CrcTablea097
    

    if {$Poly == 1021} {
        set CrcTable CrcTable1021
    } elseif {$Poly == 8005} {
        set CrcTable CrcTable8005
    } elseif {$Poly == "c867"} {
        set CrcTable CrcTablec867
    } elseif {$Poly == "0589"} {
        set CrcTable CrcTable0589
    } elseif {$Poly == "3d65"} {
        set CrcTable CrcTable3d65
    } elseif {$Poly == "8bb7"} {
        set CrcTable CrcTable8bb7
    } elseif {$Poly == "a097"} {
        set CrcTable CrcTablea097
    }
    set CrcReg 0x$Init

	set ByteLen [expr [string length $Data]/2]
	if {$ByteLen == 0} {
		set len 1
	}
	for {set j 0} {$j<$ByteLen} {incr j 1} {
		set byte 0x[string range $Data [expr $j*2] [expr $j*2+1]]
        if {$RefIn == 1} {
            set byte [CrcReflect $byte 8]
        }
        set CrcRegH [expr ($CrcReg >> 12) & 0x0F]
        set CrcReg [expr ($CrcReg << 4) & 0xFFFF]
        set CrcReg [expr $CrcReg ^ [set ${CrcTable}([expr $CrcRegH ^ (($byte>>4)&0x0F)])]]

        set CrcRegH [expr ($CrcReg >> 12) & 0x0F]
        set CrcReg [expr ($CrcReg << 4) & 0xFFFF]
        set CrcReg [expr $CrcReg ^ [set ${CrcTable}([expr $CrcRegH ^ ($byte&0x0F)])]]

    }
    
    if {$RefOut == 1} {
        set CrcReg [CrcReflect $CrcReg 16]
    }

    set CrcReg [expr $CrcReg ^ 0x$XorOut]

    return [format %04x $CrcReg]
}

######################################################################################################################
#CRC 16 封装计算
######################################################################################################################
proc crc16Ibm {Data} {
    set Name   "Crc-16, Crc-16/ARC, Crc-16/LHA"
    set Width  16
    set Poly   8005
    set Init   0000
    set RefIn  1
    set RefOut 1
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crc16Maxim {Data} {
    set Name   "Crc-16/MAXIM"
    set Width  16
    set Poly   8005
    set Init   0000
    set RefIn  1
    set RefOut 1
    set XorOut FFFF

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crc16Usb {Data} {
    set Name   "Crc-16/USB"
    set Width  16
    set Poly   8005
    set Init   FFFF
    set RefIn  1
    set RefOut 1
    set XorOut FFFF

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crc16Modbus {Data} {
    set Name   "Crc-16/MODBUS"
    set Width  16
    set Poly   8005
    set Init   FFFF
    set RefIn  1
    set RefOut 1
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crc16Ccitt {Data} {
    set Name   "Crc-16/CCITT, Crc-16/CCITT-TRUE, Crc-16/KERMIT"
    set Width  16
    set Poly   1021
    set Init   0000
    set RefIn  1
    set RefOut 1
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crc16CcittFalse {Data} {
    set Name   "Crc-16/CCITT-FAISE"
    set Width  16
    set Poly   1021
    set Init   FFFF
    set RefIn  0
    set RefOut 0
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crcA {Data} {
    set Name   Crc-A
    set Width  16
    set Poly   1021
    set Init   c6c6
    set RefIn  1
    set RefOut 1
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crc16X25 {Data} {
    set Name   "CRC-B, CRC-16/IBM-SDLC, CRC-16/ISO-HDLC, X2.5"
    set Width  16
    set Poly   1021
    set Init   FFFF
    set RefIn  1
    set RefOut 1
    set XorOut FFFF

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crcB {Data} {
    crc16X25 $Data
}

proc crc16Xmodem {Data} {
    set Name   "Crc-16/XMODEM, Crc-16/ZMODEM, Crc-16/ACORN"
    set Width  16
    set Poly   1021
    set Init   0000
    set RefIn  0
    set RefOut 0
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crc16Dnp {Data} {
    set Name   "Crc-16/DNP"
    set Width  16
    set Poly   3d65
    set Init   0000
    set RefIn  1
    set RefOut 1
    set XorOut FFFF

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crc16AugCcitt {Data} {
    set Name   "CRC-16/AUG-CCITT, CRC-16/SPI-FUJITSU"
    set Width  16
    set Poly   1021
    set Init   1d0f
    set RefIn  0
    set RefOut 0
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crc16Buypass {Data} {
    set Name   "CRC-16/BUYPASS, CRC-16/VERIFONE"
    set Width  16
    set Poly   8005
    set Init   0000
    set RefIn  0
    set RefOut 0
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crc16Cdma2000 {Data} {  
    set Name   "CRC-16/CDMA2000"
    set Width  16
    set Poly   c867
    set Init   ffff
    set RefIn  0
    set RefOut 0
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crc16Dds110   {Data} {  
    set Name   "CRC-16/DDS-100"
    set Width  16
    set Poly   8005
    set Init   800d
    set RefIn  0
    set RefOut 0
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crc16DectR    {Data} {
    set Name   "CRC-16/DECT-R, R-CRC-16"
    set Width  16
    set Poly   0589
    set Init   0000
    set RefIn  0
    set RefOut 0
    set XorOut 0001

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crc16DectX    {Data} {
    set Name   "CRC-16/DECT-X, X-CRC-16"
    set Width  16
    set Poly   0589
    set Init   0000
    set RefIn  0
    set RefOut 0
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crc16En13757 {Data} {  
    set Name   "CRC-16/EN-13757"
    set Width  16
    set Poly   3d65
    set Init   0000
    set RefIn  0
    set RefOut 0
    set XorOut ffff

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crc16Genibus {Data} { 
    set Name   "CRC-16/GENIBUS, CRC-16/EPC, CRC-16/I-CODE, CRC-16/DARC"
    set Width  16
    set Poly   1021
    set Init   ffff
    set RefIn  0
    set RefOut 0
    set XorOut ffff

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

proc crc16Mcrf4xx  {Data} { 
    set Name   "CRC-16/MCRF4XX"
    set Width  16
    set Poly   1021
    set Init   ffff
    set RefIn  1
    set RefOut 1
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crc16Riello   {Data} { 
    set Name   "CRC-16/RIELLO"
    set Width  16
    set Poly   1021
    set Init   b2aa
    set RefIn  1
    set RefOut 1
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crc16T10Dif   {Data} { 
    set Name   "CRC-16/T10-DIF"
    set Width  16
    set Poly   8bb7
    set Init   0000
    set RefIn  0
    set RefOut 0
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crc16Teledisk {Data} {
    set Name   "CRC-16/TELEDISK"
    set Width  16
    set Poly   a097
    set Init   0000
    set RefIn  0
    set RefOut 0
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}
proc crc16Tms37157 {Data} {
    set Name   "CRC-16/TMS37157"
    set Width  16
    set Poly   1021
    set Init   89ec
    set RefIn  1
    set RefOut 1
    set XorOut 0000

    set Result [crc16 $Poly $Init $RefIn $RefOut $XorOut $Data]
    
    #puts Name:\ ${Name}\nWidth:\ ${Width}\nPoly:\ ${Poly}\nInit:\ ${Init}\nRefIn:\ ${RefIn}\nRefOut:\ ${RefOut}\nXorOut\ ${XorOut}\nResult:\ ${Result}

    return $Result
}

puts "load crc16 successfully!"
