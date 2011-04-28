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

run('./validns', '-t1303720021', 't/zones/example.sec.signed');
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
like(shift @e, qr/unrecognized directive/, "unrecognized directive");
like(shift @e, qr/bad \$ORIGIN format/, "not really an origin");
like(shift @e, qr/\$ORIGIN value expected/, "empty origin");
like(shift @e, qr/garbage after valid \$ORIGIN/, "bad origin");
like(shift @e, qr/bad \$TTL format/, "not really a TTL");
like(shift @e, qr/\$TTL value expected/, "empty TTL");
like(shift @e, qr/\$TTL value expected/, "funny TTL");
like(shift @e, qr/\$TTL value is not valid/, "bad TTL");
like(shift @e, qr/\$TTL value is not valid/, "bad TTL take 2");
like(shift @e, qr/garbage after valid \$TTL/, "bad TTL take 3");
like(shift @e, qr/bad \$INCLUDE format/, "not really an include");
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

like(shift @e, qr/RRSIG\(NSEC\): cannot verify the signature/, "NSEC incomplete fallout") for 1..4;
like(shift @e, qr/there are more record types than NSEC mentions/, "NSEC incomplete");
like(shift @e, qr/RRSIG\(NSEC\): cannot verify the signature/, "NSEC lists too much fallout") for 1..4;
like(shift @e, qr/NSEC mentions SRV, but no such record found/, "NSEC lists too much");

like(shift @e, qr/RRSIG exists for non-existing type NAPTR/, "RRSIG for absent");
like(shift @e, qr/NSEC says ns2.example.sec. comes after ns1.example.sec., but ns122.example.sec. does/, "NSEC chain error");
like(shift @e, qr/RRSIG's original TTL differs from corresponding record's/, "RRSIG orig ttl bad");
like(shift @e, qr/RRSIG\(NSEC\): cannot find a signer key/, "unknown signer");
like(shift @e, qr/NSEC says www.example.sec. is the last name, but zzz.example.sec. exists/, "NSEC chain not the last");
like(shift @e, qr/NSEC says zzzz.example.sec. comes after zzz.example.sec., but nothing does/, "NSEC chain unexpected last");

is(+@e, 0, "no unaccounted errors");

done_testing;
