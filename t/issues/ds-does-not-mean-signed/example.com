example.com.            86400 IN SOA    ns.example.com. hostmaster.example.com. 1 604800 86400 2419200 604800
example.com.            86400 IN NS     ns.example.com.
foo.example.com.        86400 IN NS     ns.example.org.
foo.example.com.        86400 IN DS     45004 8 1 059D592478F4EB97496BB2294520B32A89A196BC
ns.example.com.         86400 IN A      127.0.0.1
