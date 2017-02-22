#===============================================================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
#rng for TCL
#
# random number generation
#
#Wei Zhang <d5c5ceb0@gmail.com>   2016.06.17
#
#===============================================================================
# rand NumByte smin smax
#===============================================================================

package provide crypto 1.0.0

proc rng_RandomRange { min max } {  
    # 获得[0.0,1.0)之间的随机数  
    set rd [expr rand()] 
      
    # 将$rd放大到[$min, $max)  
    set result [expr $rd * ($max - $min) + $min]  
      
    return $result  
}  
#  
#FUNC:获取[min, max)区间是随机整数  
#  
proc rng_RandomRangeInt { min max } {  
    return [expr int([rng_RandomRange $min $max])]  
}  
  
proc rand {NumByte smin smax} {
    set result ""
    for {set i 1} {$i<=$NumByte} {incr i} {
        set tmp [format "%02x" [rng_RandomRangeInt $smin $smax]]
        set result [append result $tmp]  
    }
    return [string toupper $result]
}

puts "load rng successfully!"
