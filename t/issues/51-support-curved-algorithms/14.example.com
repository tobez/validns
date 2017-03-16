$TTL 86400 ; (1 day)
$ORIGIN 14.example.com.
$INCLUDE K14.example.com.+014+01045.key;
@ IN SOA ns1.example.com. hostmaster.example.com. (
                2014012401 ; serial YYYYMMDDnn
                14400      ; refresh (4 hours)
                1800       ; retry   (30 minutes)
                1209600    ; expire  (2 weeks)
                3600       ; minimum (1 hour)
                )
 
         172800    IN   NS    ns1.example.org.
         172800    IN   NS    ns2.example.org.
 
                   IN   A     203.0.113.10
www                IN   CNAME 14.example.com.
