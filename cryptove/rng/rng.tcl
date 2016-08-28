#===============================================================================
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
    # ���[0.0,1.0)֮��������  
    set rd [expr rand()] 
      
    # ��$rd�Ŵ�[$min, $max)  
    set result [expr $rd * ($max - $min) + $min]  
      
    return $result  
}  
#  
#FUNC:��ȡ[min, max)�������������  
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
