/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2013 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

/* XXX Does not accept multiple character-strings */

static struct rr *x25_parse(char *name, long ttl, int type, char *s)
{
	struct rr_x25 *rr = getmem(sizeof(*rr));
	int i;

	rr->psdn_address = extract_text(&s, "PSDN-address");
	if (rr->psdn_address.length < 0)
		return NULL;
	if (rr->psdn_address.length > 255)
		return bitch("PSDN-address too long");
	if (rr->psdn_address.length < 4)
		return bitch("PSDN-address too short");
	for (i = 0; i < rr->psdn_address.length; i++) {
		if (!isdigit(rr->psdn_address.data[i]))
			return bitch("PSDN-address contains non-digits");
	}

	return store_record(type, name, ttl, rr);
}

static char* x25_human(struct rr *rrv)
{
	RRCAST(x25);

    return rr->psdn_address.data;
}

static struct binary_data x25_wirerdata(struct rr *rrv)
{
	RRCAST(x25);

	return compose_binary_data("b", 1, rr->psdn_address);
}

struct rr_methods x25_methods = { x25_parse, x25_human, x25_wirerdata, NULL, NULL };
