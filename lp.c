/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, 2012 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr *lp_parse(char *name, long ttl, int type, char *s)
{
	struct rr_lp *rr = getmem(sizeof(*rr));
	int preference;

	rr->preference = preference = extract_integer(&s, "LP preference");
	if (preference < 0)
		return NULL;
	rr->fqdn = extract_name(&s, "LP fqdn", 0);
	if (!rr->fqdn)
		return NULL;
	if (strcasecmp(name, rr->fqdn) == 0) {
		return bitch("LP points to itself");
	}

	if (*s) {
		return bitch("garbage after valid LP data");
	}

	return store_record(type, name, ttl, rr);
}

static char* lp_human(struct rr *rrv)
{
	RRCAST(lp);
	char s[1024];

	snprintf(s, 1024, "%d %s",
			 rr->preference, rr->fqdn);
	return quickstrdup_temp(s);
}

static struct binary_data lp_wirerdata(struct rr *rrv)
{
	RRCAST(lp);
    return compose_binary_data("2d", 1,
		rr->preference, name2wire_name(rr->fqdn));
}

struct rr_methods lp_methods = { lp_parse, lp_human, lp_wirerdata, NULL, NULL };
