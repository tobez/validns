#! /usr/bin/perl
use 5.006;
use strict;
use warnings;

use Test::More;
BEGIN { use_ok("Test::Command::Simple"); }

run('./validns', 't/zones/galaxyplus.org');
is(rc, 0, 'valid zone parses ok');

run('./validns', 't/zones/manyerrors.zone');
isnt(rc, 0, 'bad zone returns an error');
like(stderr, qr/:1: unrecognized directive/, "unrecognized directive");
like(stderr, qr/:4: class or type expected/, "nonsense line");
like(stderr, qr/:13: nsdname expected/, "empty NS");
like(stderr, qr/:14: garbage after valid NS/, "bad NS");

like(stderr, qr/:17: ip address expected/, "empty A");
like(stderr, qr/:18: garbage after valid A data/, "bad A");
like(stderr, qr/:19: ip address is not valid/, "bad A IP");
like(stderr, qr/:20: ip address expected/, "not an IP in A");
like(stderr, qr/:22: MX preference expected/, "empty MX");
like(stderr, qr/:23: MX exchange expected/, "MX without exchange");
like(stderr, qr/:24: garbage after valid MX data/, "bad MX");

done_testing;
