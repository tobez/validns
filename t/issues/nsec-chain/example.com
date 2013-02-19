$TTL	1d
$INCLUDE Kexample.com.+010+35615.key
@       IN      SOA     ns.example.com. hostmaster.example.com. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL

                IN      NS      ns1.example.net.


domain1         IN      NS      ns1.example.net.
                IN DS 2629 8 1 422D2A1FEADD36337C719964637CA08EB4C6BECB
