$TTL	1d
$ORIGIN example.com.
@       IN      SOA     ns.example.com. hostmaster.example.com. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL

                IN      NS      ns1.example.net.


domain1         IN      NS      ns1.example.net.

hyphen-middle   A 1.2.3.4           ; always ok
-starting-hyphen    A 1.2.3.4       ; ok with -p permit-starting-hyphen
------  A 1.2.3.4                   ; ok with -p permit-starting-hyphen
