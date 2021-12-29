#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#hmac api for TCL
#
#hmac api
#
#Wei Zhang <d5c5ceb0@gmail.com>   2021.12.29
#
#===============================================================================
#===============================================================================

package provide crypto 1.0.0

source [file join [file dirname [info script]] ../common/common.tcl]
source [file join [file dirname [info script]] ../hash/hash_primitive.tcl]
source [file join [file dirname [info script]] ../mac/hmac_api.tcl]

proc hkdf_extract {salt IKM hmode} {
	return [${hmode}_hmac_process $salt $IKM]
}

proc hkdf_expand {PRK info L hmode} {
	global hash_list

	set hash_digestlen [lindex [dict get $hash_list $hmode] 2]
	set counter [expr ($L - 1 + $hash_digestlen) / $hash_digestlen]

	set ret ""
	set okm ""
	for {set i 0} {$i < $counter} {incr i 1} {
		set ret [${hmode}_hmac_process $PRK ${ret}${info}[dec2hex [expr $i + 1]]]
		append okm $ret
	}

	return [string range $okm 0 [expr $L*2-1]]
}

proc hkdf_process {hmode isStrong salt ikm info L} {
	if {$isStrong == 1} {
		return [hkdf_expand $ikm $info $L $hmode]
	} else {
		set prk [hkdf_extract $salt $ikm $hmode]
		return [hkdf_expand $prk $info $L $hmode]
	}
}

proc create_hkdf {} {
	global hash_list
	foreach hash [dict key $hash_list] {
		proc ${hash}_hkdf_extract {salt IKM} {
			set func_name [lindex [info level 0] 0]
			set hmode [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
			return [hkdf_extract $salt $IKM ${hmode}]
		}

		proc ${hash}_hkdf_expand {PRK info L} {
			set func_name [lindex [info level 0] 0]
			set hmode [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
			return [hkdf_expand $PRK $info $L ${hmode}]
		}

		proc ${hash}_hkdf_process {isStrong salt ikm info L} {
			set func_name [lindex [info level 0] 0]
			set hmode [string range $func_name 0 [expr [string first _ $func_name] - 1] ]
			return [hkdf_process $hmode $isStrong $salt $ikm $info $L]
		}
	}
}

create_hkdf
puts "load hkdf successfully"
