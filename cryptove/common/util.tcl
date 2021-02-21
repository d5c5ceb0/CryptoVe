#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#util for TCL
#
#util
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
#===============================================================================

package provide crypto 1.0.0


#十进制转十六进制
proc dec2hex {dec} {
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

proc dec2hex2 {num args} {
	set y ""
	for {set i 0} {$i < $num} {incr i 1} {
		set x [lindex $args $i]
		append y [dec2hex $x]
	}
	puts $y
}

#大小端转换
proc endian {str} {
    
    set strlen [string length $str]
    if {$strlen % 2} {
        set str 0$str
    }

    set ret ""
    for {set i 0} {$i < $strlen} {incr i 2} {
        set ret [string range $str $i [expr $i+1]]$ret
    }

    return $ret
}


#字符串
#hex to bin
proc hex2bin {str} {

    set strlen [string length $str]

    set ret ""
    for {set i 0} {$i < $strlen} {incr i 2} {
        set tmp [string range $str $i [expr $i+1]]
        scan $tmp %x tmp
        set tmp [format %c $tmp]

        append ret $tmp
    }

    return $ret
}

#文件
#hex to bin
proc hex2binfile {srcfile dstfile} {

    set fns [open $srcfile r]
    set fnd [open $dstfile wb]

    gets $fns line
    puts -nonewline $fnd [hex2bin $line]

    close $fns
    close $fnd

}

proc bin2hex {str} {
	set strlen [string length $str]
	set ch ""
	for {set i 0} {$i < $strlen} {incr i 1} {
		set chr [string index $str $i]
		scan $chr %c ch
		append hex_str [format %02x $ch]
	}

	return $hex_str
}

proc bin2hexfile {srcfile dstfile} {

    set sfn [open $srcfile rb]
    set dfn [open $dstfile w]

    while {[set chr [read $sfn 1]] != ""} {
        scan $chr %c ch
        set ch [format %02x $ch]
        puts -nonewline $dfn $ch
    }

    close $sfn
    close $dfn
}
#字符串比较
proc Compare {str1 str2} {

    set str1 [string toupper $str1]
    set str2 [string toupper $str2]
    set sRes [string compare $str1 $str2]

    if {$sRes!=0} {
        return -code error "Compare unequal!\n"
    } else {
        return "Compare equal!\n"
    }
}


proc Len {str} {
    set temp1 [expr [string length $str]/2]
    set temp2 [string toupper [format "%02x" $temp1]]
    return $temp2 
}

proc strcat {str1 args} {
    foreach str $args {
        append str1 $str
    }

    return $str1
}

proc strsp {str not} {

    set strlen [string length $str]
    if {$strlen % 2} {
        set str 0$str
    }

    set ret ""
    for {set i 0} {$i < ([string length $str]-2)} {incr i 2} {
        append ret [string range $str $i $i+1]$not
    }
    
    append ret [string range $str $i $i+1]
    return $ret
}

proc hexstr2binfile {str dstfile} {
    set fnd [open $dstfile wb]
    puts -nonewline $fnd [hex2bin $str]
    close $fnd
}

