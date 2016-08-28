#===============================================================================
# crc test case for TCL
#
# crc test
#
# Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
# functions:
# test_crc16
#===============================================================================
#

source [file join [file dirname [info script]] ../cryptove.tcl]

proc test_crc16 {} {
	set m 0102030405060708090a0b0c0d0e0f
	#crc-16/ibm
	set r [crc16Ibm $m]
	if {[cmp $r 170a]} {
		puts $r
		puts 170a
		return -code error "crc-16/ibm error"
		
	}
	puts "test crc-16/imb successfully!"

	#crc-16/maxim
	set r [crc16Maxim $m]
	if {[cmp $r e8f5]} {
		puts $r
		puts e8f5
		return -code error "crc-16/maxim error"
	}
	puts "test crc-16/maxim successfully!"

	#crc-16/usb
	set r [crc16Usb $m]
	if {[cmp $r 57b5]} {
		puts $r
		puts 57b5
		return -code error "crc-16/usb error"
	}
	puts "test crc-16/usb successfully!"

	#crc-16/modbus
	set r [crc16Modbus $m]
	if {[cmp $r a84a]} {
		puts $r
		puts a84a
		return -code error "crc-16/modbus error"
	}
	puts "test crc-16/modbus successfully!"

	#crc-16/ccitt
	set r [crc16Ccitt $m]
	if {[cmp $r bc40]} {
		puts $r
		puts bc40
		return -code error "crc-16/ccitt error"
	}
	puts "test crc-16/ccitt successfully!"

	#crc-16/ccitt-false
	set r [crc16CcittFalse $m]
	if {[cmp $r 1ffe]} {
		puts $r
		puts 1ffe
		return -code error "crc-16/ccitt-false error"
	}
	puts "test crc-16/ccitt-false successfully!"

	#crc-16/x25
	set r [crc16X25 $m]
	if {[cmp $r 80cd]} {
		puts $r
		puts 80cd
		return -code error "crc-16/x25 error"
	}
	puts "test crc-16/x25 successfully!"

	#crc-16/xmodem
	set r [crc16Xmodem $m]
	if {[cmp $r 513d]} {
		puts $r
		puts 513d
		return -code error "crc-16/xmodem error"
	}
	puts "test crc-16/xmodem successfully!"

	#crc-16/dnp
	set r [crc16Dnp $m]
	if {[cmp $r 10ec]} {
		puts $r
		puts 10ec
		return -code error "crc-16/dnp error"
	}
	puts "test crc-16/dnp successfully!"
}
