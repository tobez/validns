$ORIGIN example.com.
$TTL    1d
@       IN      SOA     ns.example.com. hostmaster.example.com. (
                              1         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
                IN      NS      ns1.example.com.

host/1  IN      CNAME   example.net.
host/2       IN A       127.0.0.1
host/3  IN      NS      ns2.example.org.
1       IN      CNAME   1.host/3.example.com.
2       IN      CNAME   2.host/3.example.com.
host/4       IN MX 5 example.net.
host/5       IN AAAA   2001:2010:1::feef
host/6  IN      NS      host/28.example.net.
