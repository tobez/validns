#! /usr/bin/perl
use 5.006;
use strict;
use warnings;

use Test::More;
BEGIN { use_ok("Test::Command::Simple"); }

unless (*run{CODE})
{
	done_testing;
	exit(0);
}

my @e;

run('./validns', 't/zones/galaxyplus.org');
is(rc, 0, 'valid zone parses ok');

run('./validns', '-t1320094109', 't/zones/example.sec.signed');
is(rc, 0, 'valid signed zone parses ok');

run('./validns', '-t1303720010', 't/zones/example.sec.signed');
isnt(rc, 0, 'valid signed zone with timestamps in the future');
@e = split /\n/, stderr;
like(shift @e, qr/signature is too new/, "signature is too new");

run('./validns', '-t1355314832', 't/zones/example.sec.signed');
isnt(rc, 0, 'valid signed zone with timestamps in the past');
@e = split /\n/, stderr;
like(shift @e, qr/signature is too old/, "signature is too old");

run('./validns', '-s', '-pall', 't/zones/manyerrors.zone');
isnt(rc, 0, 'bad zone returns an error');
@e = split /\n/, stderr;

# main.c
like(shift @e, qr/unrecognized directive: \$FUNNYDIRECTIVE/, "unrecognized directive 1");
like(shift @e, qr/unrecognized directive: \$ORIGINBUTNOTREALLY/, "unrecognized directive 2");
like(shift @e, qr/bad \$ORIGIN format/, "not really an origin");
like(shift @e, qr/\$ORIGIN value expected/, "empty origin");
like(shift @e, qr/garbage after valid \$ORIGIN/, "bad origin");
like(shift @e, qr/unrecognized directive: \$TTLAST/, "unrecognized directive 3");
like(shift @e, qr/bad \$TTL format/, "not really a TTL");
like(shift @e, qr/\$TTL value expected/, "empty TTL");
like(shift @e, qr/\$TTL value expected/, "funny TTL");
like(shift @e, qr/\$TTL value is not valid/, "bad TTL");
like(shift @e, qr/\$TTL value is not valid/, "bad TTL take 2");
like(shift @e, qr/garbage after valid \$TTL/, "bad TTL take 3");
like(shift @e, qr/unrecognized directive: \$INCLUDESSIMO/, "unrecognized directive 4");
like(shift @e, qr/bad \$INCLUDE format/, "not really an include");
like(shift @e, qr/unrecognized directive: \$/, "unrecognized directive 5");
like(shift @e, qr/unrecognized directive: \$/, "unrecognized directive 6");
# TODO once INCLUDE is implemented, add more tests
## TODO continue main.c at "cannot assume previous name"

like(shift @e, qr/class or type expected/, "nonsense line");
like(shift @e, qr/the first record in the zone must be an SOA record/, "non-SOA 1");
like(shift @e, qr/the first record in the zone must be an SOA record/, "non-SOA 2");
like(shift @e, qr/serial is out of range/, "out of range serial");
like(shift @e, qr/there could only be one SOA in a zone/, "another SOA");
like(shift @e, qr/name server domain name expected/, "empty NS");
like(shift @e, qr/garbage after valid NS/, "bad NS");
like(shift @e, qr/IPv4 address is not valid/, "empty A");
like(shift @e, qr/garbage after valid A data/, "bad A");
like(shift @e, qr/cannot parse IPv4 address/, "bad A IP");
like(shift @e, qr/IPv4 address is not valid/, "not an IP in A");
like(shift @e, qr/IPv6 address is not valid/, "empty AAAA");
like(shift @e, qr/garbage after valid AAAA data/, "bad AAAA");
like(shift @e, qr/IPv6 address is not valid/, "bad AAAA IP");
like(shift @e, qr/IPv6 address is not valid/, "not an IP in AAAA");
like(shift @e, qr/MX preference expected/, "empty MX");
like(shift @e, qr/MX exchange expected/, "MX without exchange");
like(shift @e, qr/garbage after valid MX data/, "bad MX");
like(shift @e, qr/outside.org. does not belong to zone galaxyplus.org./, "outsider");
like(shift @e, qr/long.outside.org. does not belong to zone galaxyplus.org./, "long outsider");
like(shift @e, qr/outsidegalaxyplus.org. does not belong to zone galaxyplus.org./, "tricky outsider");
like(shift @e, qr/there could only be one SOA in a zone/, "another SOA at the end");
like(shift @e, qr/record name is not valid/, "wildcard is the middle");
like(shift @e, qr/record name: bad wildcard/, "bad wildcard");
like(shift @e, qr/name cannot start with a dot/, "dot-something");
like(shift @e, qr/name cannot start with a dot/, "dot-dot");

## actual validations done after parsing
like(shift @e, qr/CNAME and other data/, "CNAME+CNAME");
like(shift @e, qr/CNAME and other data/, "CNAME+something else");
like(shift @e, qr/there should be at least two NS records/, "NS limit");
like(shift @e, qr/TTL values differ within an RR set/, "TTL conflict");

is(+@e, 0, "no unaccounted errors");
#like(stdout, qr/validation errors: XX/, "error count");

run('./validns', '-s', 't/zones/example.sec.signed.with-errors');
isnt(rc, 0, 'bad signed zone returns an error');
@e = split /\n/, stderr;

like(shift @e, qr/MX exists, but NSEC does not mention it/, "NSEC incomplete");
like(shift @e, qr/NSEC mentions SRV, but no such record found/, "NSEC lists too much");
like(shift @e, qr/RRSIG exists for non-existing type NAPTR/, "RRSIG for absent");
like(shift @e, qr/RRSIG's original TTL differs from corresponding record's/, "RRSIG orig ttl bad");
like(shift @e, qr/RRSIG\(NSEC\): cannot find a signer key/, "unknown signer");
like(shift @e, qr/NSEC says ns1.example.sec. comes after mail.example.sec., but nosuch.example.sec. does/, "NSEC chain error");
like(shift @e, qr/NSEC says ns2.example.sec. comes after ns1.example.sec., but ns122.example.sec. does/, "NSEC chain error");
like(shift @e, qr/NSEC says www.example.sec. is the last name, but zzz.example.sec. exists/, "NSEC chain not the last");
like(shift @e, qr/NSEC says zzzz.example.sec. comes after zzz.example.sec., but nothing does/, "NSEC chain unexpected last");
like(shift @e, qr/RRSIG\(NSEC\): cannot verify the signature/, "NSEC incomplete fallout") for 1..4;
like(shift @e, qr/RRSIG\(NSEC\): cannot verify the signature/, "NSEC lists too much fallout") for 1..4;

is(+@e, 0, "no unaccounted errors");

# RFC 2181 policy checks
run('./validns', '-p', 'all', '-z', 'example1.jp', 't/zones/mx-ns-alias');
is(rc, 0, 'parses OK if we cannot determine the fact of aliasing');
run('./validns', '-p', 'all', '-z', 'example.jp', 't/zones/mx-ns-alias');
isnt(rc, 0, 'RFC 2181 policy checks are active');
@e = split /\n/, stderr;
like(shift @e, qr/NS data is an alias/, "NS data is an alias");
like(shift @e, qr/MX exchange is an alias/, "MX exchange is an alias");
is(+@e, 0, "no unaccounted errors for 2181 policy checks");

run('./validns', '-p', 'mx-alias', '-p', 'ns-alias', '-z', 'example.jp', 't/zones/mx-ns-alias');
isnt(rc, 0, 'RFC 2181 policy checks are active (individually activated)');
@e = split /\n/, stderr;
like(shift @e, qr/NS data is an alias/, "NS data is an alias");
like(shift @e, qr/MX exchange is an alias/, "MX exchange is an alias");
is(+@e, 0, "no unaccounted errors for individually activated checks");

run('./validns', '-p', 'mx-alias', '-z', 'example.jp', 't/zones/mx-ns-alias');
isnt(rc, 0, 'mx-alias policy check');
@e = split /\n/, stderr;
like(shift @e, qr/MX exchange is an alias/, "MX exchange is an alias");
is(+@e, 0, "no unaccounted errors for mx-alias check");

run('./validns', '-p', 'ns-alias', '-z', 'example.jp', 't/zones/mx-ns-alias');
isnt(rc, 0, 'ns-alias policy check');
@e = split /\n/, stderr;
like(shift @e, qr/NS data is an alias/, "NS data is an alias");
is(+@e, 0, "no unaccounted errors for ns-alias check");

# RP policy
run('./validns', '-p', 'all', '-z', 'example.jp', 't/zones/rp-policy');
isnt(rc, 0, 'RP policy check is active');
@e = split /\n/, stderr;
like(shift @e, qr/RP TXT.*?does not exist/, "RP TXT is not there");
is(+@e, 0, "no unaccounted errors for RP policy checks");

run('./validns', '-z', 'example.jp', 't/zones/rp-policy');
is(rc, 0, 'RP policy check is inactive');

run('./validns', '-v', 't/zones/ttl-regression.zone');
is(rc, 0, 'ttl regression parses OK');
like(stderr, qr/ns\.example\.com\.\s+IN\s+600\s+A\s+192\.0\.2\.1/,
	"Default TTL changes correctly");

run('./validns', '-v', 't/zones/ttl.zone');
is(rc, 0, 'ttl test parses OK');
like(stderr, qr/ns\.example\.com\.\s+IN\s+600\s+A\s+192\.0\.2\.1/,
	"Default TTL changes correctly");
like(stderr, qr/\s+example\.com\.\s+IN\s+200\s+NS\s+ns\.example\.com\./,
	"TTL without default picked up correctly");

done_testing;
