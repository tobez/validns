/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr* dhcid_parse(char *name, long ttl, int type, char *s)
{
	struct rr_dhcid *rr = getmem(sizeof(*rr));
	struct binary_data data;

	data = extract_base64_binary_data(&s, "rdata");
	if (data.length < 0)	return NULL;

	if (data.length < 3)
		return bitch("rdata too short");

	rr->id_type = data.data[0]*256 + data.data[1];
	if (rr->id_type > 2)
		return bitch("unsupported identifier type %s", rr->id_type);

	rr->digest_type = data.data[2];
	if (rr->digest_type != 1)
		return bitch("unsupported digest type %s", rr->digest_type);

	if (data.length != 35)
		return bitch("wrong digest length, must be 32 for SHA-256");

	/* let's cheat a bit */
	data.length -= 3;
	data.data += 3;
	rr->digest = data;

	if (*s) {
		return bitch("garbage after valid DHCID data");
	}
	return store_record(type, name, ttl, rr);
}

static char* dhcid_human(struct rr *rrv)
{
    return "...";
}

static struct binary_data dhcid_wirerdata(struct rr *rrv)
{
	RRCAST(dhcid);

	return compose_binary_data("21d", 1,
		rr->id_type, rr->digest_type, rr->digest);
}

struct rr_methods dhcid_methods = { dhcid_parse, dhcid_human, dhcid_wirerdata, NULL, NULL };
