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

run('./validns', 't/zones/galaxyplus.org');
is(rc, 0, 'valid zone parses ok');

run('./validns', '-s', 't/zones/manyerrors.zone');
isnt(rc, 0, 'bad zone returns an error');
my @e = split /\n/, stderr;

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
like(shift @e, qr/nsdname expected/, "empty NS");
like(shift @e, qr/garbage after valid NS/, "bad NS");
like(shift @e, qr/ip address expected/, "empty A");
like(shift @e, qr/garbage after valid A data/, "bad A");
like(shift @e, qr/ip address is not valid/, "bad A IP");
like(shift @e, qr/ip address expected/, "not an IP in A");
like(shift @e, qr/MX preference expected/, "empty MX");
like(shift @e, qr/MX exchange expected/, "MX without exchange");
like(shift @e, qr/garbage after valid MX data/, "bad MX");

## actual validations done after parsing
like(shift @e, qr/there should be at least two NS records/, "NS limit");

is(+@e, 0, "no unaccounted errors");
#like(stdout, qr/validation errors: XX/, "error count");

done_testing;
