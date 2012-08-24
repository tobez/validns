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

for my $threads ("", qw(-n2 -n4 -n6 -n8)) {
my @threads;
push @threads, $threads if $threads;
run('./validns', @threads, 't/zones/galaxyplus.org');
is(rc, 0, 'valid zone parses ok');

run('./validns', @threads, '-t1320094109', 't/zones/example.sec.signed');
is(rc, 0, 'valid signed zone parses ok');

run('./validns', @threads, '-t1303720010', 't/zones/example.sec.signed');
isnt(rc, 0, 'valid signed zone with timestamps in the future');
@e = split /\n/, stderr;
like(shift @e, qr/signature is too new/, "signature is too new");

run('./validns', @threads, '-t1355314832', 't/zones/example.sec.signed');
isnt(rc, 0, 'valid signed zone with timestamps in the past');
@e = split /\n/, stderr;
like(shift @e, qr/signature is too old/, "signature is too old");

run('./validns', @threads, '-s', '-pall', 't/zones/manyerrors.zone');
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

like(shift @e, qr/bad SHA-256 hash length/, "TLSA SHA-256");
like(shift @e, qr/bad SHA-512 hash length/, "TLSA SHA-512");
like(shift @e, qr/certificate association data: hex data does not represent whole number of bytes/, "TLSA nibbles");

like(shift @e, qr/bad certificate usage field/, "TLSA certificate usage");
like(shift @e, qr/TTL is not valid/, "TLSA certificate usage fallout");
like(shift @e, qr/certificate usage field expected/, "TLSA certificate usage");
like(shift @e, qr/TTL is not valid/, "TLSA certificate usage fallout");

like(shift @e, qr/bad selector field/, "TLSA selector");
like(shift @e, qr/TTL is not valid/, "TLSA selector fallout");
like(shift @e, qr/selector field expected/, "TLSA selector");
like(shift @e, qr/TTL is not valid/, "TLSA selector fallout");

like(shift @e, qr/bad matching type field/, "TLSA matching type");
like(shift @e, qr/TTL is not valid/, "TLSA matching type fallout");
like(shift @e, qr/matching type field expected/, "TLSA matching type");
like(shift @e, qr/TTL is not valid/, "TLSA matching type fallout");

like(shift @e, qr/outside.org. does not belong to zone galaxyplus.org./, "outsider");
like(shift @e, qr/long.outside.org. does not belong to zone galaxyplus.org./, "long outsider");
like(shift @e, qr/outsidegalaxyplus.org. does not belong to zone galaxyplus.org./, "tricky outsider");
like(shift @e, qr/bad algorithm 177/, "bad CERT algorithm");
like(shift @e, qr/bad or unsupported algorithm meow/, "bad CERT algorithm mnemonic");
like(shift @e, qr/bad certificate type 100000/, "bad CERT type");
like(shift @e, qr/is reserved by IANA/, "reserved CERT type");
like(shift @e, qr/certificate type 700 is unassigned/, "unassigned CERT type");
like(shift @e, qr/bad certificate type meow/, "bad CERT type");
like(shift @e, qr/bad key tag/, "bad key tag");
like(shift @e, qr/certificate expected/, "bad base64");
like(shift @e, qr/there could only be one SOA in a zone/, "another SOA at the end");
like(shift @e, qr/record name is not valid/, "wildcard is the middle");
like(shift @e, qr/record name: bad wildcard/, "bad wildcard");
like(shift @e, qr/name cannot start with a dot/, "dot-something");
like(shift @e, qr/name cannot start with a dot/, "dot-dot");
like(shift @e, qr/garbage after valid DNAME data/, "DNAME garbage");

## actual validations done after parsing
like(shift @e, qr/CNAME and other data/, "CNAME+CNAME");
like(shift @e, qr/CNAME and other data/, "CNAME+something else");
like(shift @e, qr/there should be at least two NS records/, "NS limit");
like(shift @e, qr/not a proper prefixed DNS domain name/, "TLSA host 1");
like(shift @e, qr/not a proper prefixed DNS domain name/, "TLSA host 2");

like(shift @e, qr/TTL values differ within an RR set/, "TTL conflict");
like(shift @e, qr/multiple DNAMEs/, "Multiple DNAMEs");
like(shift @e, qr/DNAME must not have any children \(but something.zzzz3.galaxyplus.org. exists\)/, "DNAME with children");
like(shift @e, qr/CNAME and other data/, "DNAME+CNAME");
like(shift @e, qr/DNAME must not have any children \(but z.zzzz5.galaxyplus.org. exists\)/, "DNAME with children 2");

is(+@e, 0, "no unaccounted errors");
#like(stdout, qr/validation errors: XX/, "error count");

run('./validns', @threads, '-s', 't/zones/example.sec.signed.with-errors');
isnt(rc, 0, 'bad signed zone returns an error');
@e = split /\n/, stderr;

like(shift @e, qr/wrong GOST .* digest length/, "wrong GOST digest length");
like(shift @e, qr/MX exists, but NSEC does not mention it/, "NSEC incomplete");
like(shift @e, qr/NSEC mentions SRV, but no such record found/, "NSEC lists too much");
like(shift @e, qr/RRSIG exists for non-existing type NAPTR/, "RRSIG for absent");
like(shift @e, qr/RRSIG's original TTL differs from corresponding record's/, "RRSIG orig ttl bad");
like(shift @e, qr/RRSIG\(NSEC\): cannot find a signer key/, "unknown signer");
like(shift @e, qr/NSEC says mail.example.sec. comes after example.sec., but ghost.example.sec. does/, "NSEC chain error");
like(shift @e, qr/NSEC says ns1.example.sec. comes after mail.example.sec., but nosuch.example.sec. does/, "NSEC chain error");
like(shift @e, qr/NSEC says ns2.example.sec. comes after ns1.example.sec., but ns122.example.sec. does/, "NSEC chain error");
like(shift @e, qr/NSEC says www.example.sec. is the last name, but zzz.example.sec. exists/, "NSEC chain not the last");
like(shift @e, qr/NSEC says zzzz.example.sec. comes after zzz.example.sec., but nothing does/, "NSEC chain unexpected last");
like(shift @e, qr/RRSIG\(NSEC\): cannot verify the signature/, "NSEC incomplete fallout") for 1..4;
like(shift @e, qr/RRSIG\(NSEC\): cannot verify the signature/, "NSEC lists too much fallout") for 1..4;

is(+@e, 0, "no unaccounted errors");

# RFC 2181 policy checks
run('./validns', @threads, '-p', 'all', '-z', 'example1.jp', 't/zones/mx-ns-alias');
is(rc, 0, 'parses OK if we cannot determine the fact of aliasing');
run('./validns', @threads, '-p', 'all', '-z', 'example.jp', 't/zones/mx-ns-alias');
isnt(rc, 0, 'RFC 2181 policy checks are active');
@e = split /\n/, stderr;
like(shift @e, qr/NS data is an alias/, "NS data is an alias");
like(shift @e, qr/MX exchange is an alias/, "MX exchange is an alias");
is(+@e, 0, "no unaccounted errors for 2181 policy checks");

run('./validns', @threads, '-p', 'mx-alias', '-p', 'ns-alias', '-z', 'example.jp', 't/zones/mx-ns-alias');
isnt(rc, 0, 'RFC 2181 policy checks are active (individually activated)');
@e = split /\n/, stderr;
like(shift @e, qr/NS data is an alias/, "NS data is an alias");
like(shift @e, qr/MX exchange is an alias/, "MX exchange is an alias");
is(+@e, 0, "no unaccounted errors for individually activated checks");

run('./validns', @threads, '-p', 'mx-alias', '-z', 'example.jp', 't/zones/mx-ns-alias');
isnt(rc, 0, 'mx-alias policy check');
@e = split /\n/, stderr;
like(shift @e, qr/MX exchange is an alias/, "MX exchange is an alias");
is(+@e, 0, "no unaccounted errors for mx-alias check");

run('./validns', @threads, '-p', 'ns-alias', '-z', 'example.jp', 't/zones/mx-ns-alias');
isnt(rc, 0, 'ns-alias policy check');
@e = split /\n/, stderr;
like(shift @e, qr/NS data is an alias/, "NS data is an alias");
is(+@e, 0, "no unaccounted errors for ns-alias check");

# RP policy
run('./validns', @threads, '-p', 'all', '-z', 'example.jp', 't/zones/rp-policy');
isnt(rc, 0, 'RP policy check is active');
@e = split /\n/, stderr;
like(shift @e, qr/RP TXT.*?does not exist/, "RP TXT is not there");
is(+@e, 0, "no unaccounted errors for RP policy checks");

run('./validns', @threads, '-z', 'example.jp', 't/zones/rp-policy');
is(rc, 0, 'RP policy check is inactive');

run('./validns', @threads, '-v', 't/zones/ttl-regression.zone');
is(rc, 0, 'ttl regression parses OK');
like(stderr, qr/ns\.example\.com\.\s+IN\s+600\s+A\s+192\.0\.2\.1/,
	"Default TTL changes correctly");

run('./validns', @threads, '-v', 't/zones/misc-regression.zone');
is(rc, 0, 'misc regression parses OK');
like(stderr, qr/"alias"/, "We parse \\nnn in text correctly");
like(stderr, qr/"";"/, "We parse \\\" in text correctly");

run('./validns', @threads, '-v', 't/zones/ttl.zone');
is(rc, 0, 'ttl test parses OK');
like(stderr, qr/ns\.example\.com\.\s+IN\s+600\s+A\s+192\.0\.2\.1/,
	"Default TTL changes correctly");
like(stderr, qr/\s+example\.com\.\s+IN\s+200\s+NS\s+ns\.example\.com\./,
	"TTL without default picked up correctly");

# DNSKEY extra checks
run('./validns', @threads, 't/zones/dnskey-exponent.zone');
is(rc, 0, 'dnskey parses OK without policy checks');
run('./validns', @threads, '-p', 'all', 't/zones/dnskey-exponent.zone');
isnt(rc, 0, 'dnskey extra checks fail');
@e = split /\n/, stderr;
like(shift @e, qr/leading zero octets in public key exponent/, "leading zeroes in exponent 1");
like(shift @e, qr/leading zero octets in public key exponent/, "leading zeroes in exponent 2");
is(+@e, 0, "no unaccounted errors for DNSKEY policy checks");

# issue 25: https://github.com/tobez/validns/issues/25
run('./validns', @threads, '-t1345815800', 't/issues/25-nsec/example.sec.signed');
is(rc, 0, 'issue 25 did not come back');

}

done_testing;
