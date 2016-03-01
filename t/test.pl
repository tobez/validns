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

run('./validns', @threads, '-t1381239017', 't/zones/example.sec.signed');
is(rc, 0, 'valid signed zone parses ok');

run('./validns', @threads, '-t1303720010', 't/zones/example.sec.signed');
isnt(rc, 0, 'valid signed zone with timestamps in the future');
@e = split /\n/, stderr;
like(shift @e, qr/signature is too new/, "signature is too new");

run('./validns', @threads, '-t1421410832', 't/zones/example.sec.signed');
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

run('./validns', @threads, '-s', '-t1320094109', 't/zones/example.sec.signed.with-errors');
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
like(shift @e, qr/RRSIG\(NSEC\): bad signature/, "NSEC incomplete fallout") for 1..4;
like(shift @e, qr/RRSIG\(NSEC\): bad signature/, "NSEC lists too much fallout") for 1..4;

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

# issue 36: https://github.com/tobez/validns/issues/36 - $include implementation
run('./validns', @threads, 't/issues/36-include/empty-include.zone');
isnt(rc, 0, 'empty include detected');
@e = split /\n/, stderr;
like(shift @e, qr/\bINCLUDE directive with empty file name\b/, "Expected error with empty INCLUDE");
is(+@e, 0, "no unaccounted errors for empty include");

run('./validns', @threads, 't/issues/36-include/missing-include.zone');
isnt(rc, 0, 'missing include detected');
@e = split /\n/, stderr;
like(shift @e, qr/\bNo such file or directory\b/, "Expected error with missing INCLUDE file");
is(+@e, 0, "no unaccounted errors for missing include");

run('./validns', @threads, '-v', 't/issues/36-include/include.zone');
is(rc, 0, 'zone with nested includes parses ok');
@e = split /\n/, stderr;
for my $rx ((qr/\d:\s+example\.com\.\s+IN\s+\d+\s+NS\s+ns\.example\.com\./,
			 qr/\d:\s+inc1\.example\.com\.\s+IN\s+\d+\s+A\s+11\.11\.11\.11/,
			 qr/\d:\s+inc2\.inc1\.example\.com\.\s+IN\s+\d+\s+A\s+55\.55\.55\.55/,
			 qr/\d:\s+inc1\.example\.com\.\s+IN\s+\d+\s+AAAA\s+1111::1111/,
			 qr/\d:\s+example\.com\.\s+IN\s+\d+\s+A\s+99\.99\.99\.99/))
{
	my $ok = 0;
	for my $e (@e) {
		$ok = 1 if $e =~ $rx;
	}
	is($ok, 1, "found expected record with correct ORIGIN tracked across INCLUDEs");
}

# issue 21: https://github.com/tobez/validns/issues/21
run('./validns', @threads, '-t1345815800', 't/issues/21-nsec3-without-corresponding/example.sec.signed');
is(rc, 0, 'issue 21 did not come back');

# issue 24: https://github.com/tobez/validns/issues/24
run('./validns', @threads, '-t1345815800', 't/issues/24-delegated-nsec3/example.sec.signed');
is(rc, 0, 'issue 24 did not come back');

# issue 25: https://github.com/tobez/validns/issues/25
run('./validns', @threads, '-t1345815800', 't/issues/25-nsec/example.sec.signed');
is(rc, 0, 'issue 25 did not come back');

# issue 41: https://github.com/tobez/validns/issues/41
run('./validns', @threads, '-t1345815800', '-pksk-exists', 't/issues/25-nsec/example.sec.signed');
isnt(rc, 0, 'KSK policy check fails');
@e = split /\n/, stderr;
like(shift @e, qr/\bNo KSK found\b/, "KSK policy check produces expected error output");
is(+@e, 0, "no unaccounted errors for KSK policy check");

run('./validns', @threads, '-t1435671103', '-pksk-exists', 't/issues/41-ksk-policy-check/example.sec.signed');
is(rc, 0, 'signed zone with KSK parses ok when KSK policy check is active');

run('./validns', @threads, '-pksk-exists', 't/zones/galaxyplus.org');
is(rc, 0, 'unsigned zone ignores KSK policy checks');

# issue 26: https://github.com/tobez/validns/issues/26
run('./validns', @threads, '-t1349357570', 't/issues/26-spurios-glue/example.sec.signed.no-optout');
is(rc, 0, 'issue 26 did not come back (NSEC3 NO optout)');
run('./validns', @threads, '-t1349357570', 't/issues/26-spurios-glue/example.sec.signed.optout');
is(rc, 0, 'issue 26 did not come back (NSEC3 optout)');
run('./validns', @threads, '-t1349358570', 't/issues/26-spurios-glue/example.sec.signed.nsec');
is(rc, 0, 'issue 26 did not come back (NSEC)');

# issues about NSEC chain validation raised by Daniel Stirnimann
run('./validns', @threads, '-t1361306089', 't/issues/nsec-chain/example.com.signed');
is(rc, 0, 'all is good when all NSEC are there');
run('./validns', @threads, '-t1361306089', 't/issues/nsec-chain/example.com.signed-without-first-nsec');
isnt(rc, 0, 'zone without first NSEC returns an error');
@e = split /\n/, stderr;
is(scalar @e, 1, "only one error here");
like(shift @e, qr/apex NSEC not found/, "apex NSEC not found");
run('./validns', @threads, '-t1361306089', 't/issues/nsec-chain/example.com.signed-without-last-nsec');
isnt(rc, 0, 'zone without an NSEC returns an error');
@e = split /\n/, stderr;
is(scalar @e, 1, "only one error here");
like(shift @e, qr/broken NSEC chain example.com. -> domain1.example.com./, "broken NSEC chain detected");

# IPSECKEY tests
run('./validns', @threads, 't/zones/ipseckey-errors');
isnt(rc, 0, 'bad zone returns an error');
@e = split /\n/, stderr;
like(shift @e, qr/precedence expected/, "bad-precedence 1");
like(shift @e, qr/precedence range is not valid/, "bad-precedence 2");
like(shift @e, qr/gateway type expected/, "bad-gw-type 1");
like(shift @e, qr/gateway type is not valid/, "bad-gw-type 2");
like(shift @e, qr/algorithm expected/, "bad-algo 1");
like(shift @e, qr/algorithm is not valid/, "bad-algo 2");
like(shift @e, qr/gateway must be "\." for gateway type 0/, "gw-not-dot");
like(shift @e, qr/cannot parse gateway\/IPv4/, "bad-ip4 1");
like(shift @e, qr/gateway\/IPv4 is not valid/, "bad-ip4 2");
like(shift @e, qr/gateway\/IPv4 is not valid/, "bad-ip4 3");
like(shift @e, qr/cannot parse gateway\/IPv6/, "bad-ip6 1");
like(shift @e, qr/gateway\/IPv6 is not valid/, "bad-ip6 2");
like(shift @e, qr/cannot parse gateway\/IPv6/, "bad-ip6 3");
like(shift @e, qr/cannot parse gateway\/IPv6/, "bad-ip6 4");
like(shift @e, qr/garbage after valid IPSECKEY data/, "garbage-key");

# Verify that "." is 00 and not 00 00
run('./validns', @threads, '-t1361306089', 't/issues/dot-is-single-zero/example.sec.signed');
is(rc, 0, 'dot is zero, all is good');

# Check rare RRs
run('./validns', @threads, '-t1365591600', 't/issues/lots-of-rare-rrs/all.rr.org');
is(rc, 0, 'rare RRs are parsed correctly, all is good');

# Stuff containing '/' in various places (issue #29)
run('./validns', @threads, 't/issues/29-slash/example.com');
isnt(rc, 0, 'zone with slashes returns an error');
@e = split /\n/, stderr;

like(shift @e, qr/host name contains '\/'/, "slash-A");
like(shift @e, qr/host name contains '\/'/, "slash-MX");
like(shift @e, qr/host name contains '\/'/, "slash-AAAA");
like(shift @e, qr/NS data contains '\/'/, "NS-slash");

# DS does not mean the zone is signed
run('./validns', @threads, 't/issues/ds-does-not-mean-signed/example.com');
is(rc, 0, 'DS does not mean zone is signed');

# issue 32: support ECDSA and SHA-256 for SSHFP: https://github.com/tobez/validns/issues/32
run('./validns', @threads, '-t1378203490', 't/issues/32-sshfp-ecdsa-sha-256/example.sec.signed');
is(rc, 0, 'issue 32: SSHFP supports ECDSA and SHA-256');

# issue 34: multiple time specifications
run('./validns', @threads, ('-t1381239017') x 32, 't/zones/example.sec.signed');
is(rc, 0, 'valid signed zone parses ok');

run('./validns', @threads, ('-t1421410832') x 33, 't/zones/example.sec.signed');
isnt(rc, 0, 'too many time specs');
@e = split /\n/, stderr;
like(shift @e, qr/too many -t/, "too many -t");

run('./validns', @threads, '-t1381239017', '-t1303720010', 't/zones/example.sec.signed');
isnt(rc, 0, 'multitime: valid signed zone with timestamps in the future');
@e = split /\n/, stderr;
like(shift @e, qr/signature is too new/, "multitime: signature is too new");

run('./validns', @threads, '-t1381239017', '-t1421410832', 't/zones/example.sec.signed');
isnt(rc, 0, 'multitime: valid signed zone with timestamps in the past');
@e = split /\n/, stderr;
like(shift @e, qr/signature is too old/, "multitime: signature is too old");

run('./validns', @threads, '-t1447282800','-s', 't/issues/46-policy_ds_requires_ns/de.test.signed_ds_without_ns');
is(rc, 0, 'policy ds-requires-ns: ds without ns gets not detected, when policy is not active');
unlike(stderr, qr/DS-RR without corresponding NS-RR/m, "policy ds-requires-ns: DS-RR without corresponding NS-RR detected");

run('./validns', @threads, '-t1447282800', '-pds-requires-ns','-s', 't/issues/46-policy_ds_requires_ns/de.test.signed_ds_without_ns');
isnt(rc, 0, 'policy ds-requires-ns: ds without ns gets detected, when policy is active');
like(stderr, qr/DS-RR without corresponding NS-RR/m, "policy ds-requires-ns: DS-RR without corresponding NS-RR detected");

run('./validns', @threads, '-t1447369200', '-pds-requires-ns','-s', 't/issues/46-policy_ds_requires_ns/de.test.signed_ds_with_1_ns');
isnt(rc, 0, 'policy ds-requires-ns: ds with only 1 ns gets detected, when policy is active');
like(stderr, qr/DS-RR with less than 2 corresponding NS-RR/m, "policy ds-requires-ns: DS-RR without corresponding NS-RR detected");

run('./validns', @threads, '-t1447282800', '-pds-requires-ns','-s', 't/issues/46-policy_ds_requires_ns/de.test.signed_ok');
is(rc, 0, 'policy ds-requires-ns: zone without error and active policy returns 0');
unlike(stderr, qr/DS-RR without corresponding NS-RR/m, "policy ds-requires-ns: zone without error does not moan an error");

}

done_testing;
