$ORIGIN inc1 ; i.e., inc1.example.com.
@ A 11.11.11.11
$INCLUDE inc2.inc ; still relative to the zone file, not to this dir
; should be back to this origin
@ AAAA 1111::1111
