/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "common.h"
#include "rr.h"

static void *ns_parse(char *name, long ttl, int type, char *s)
{
	struct rr_ns *rr = getmem(sizeof(*rr));

	rr->nsdname = extract_name(&s, "nsdname");
	if (!rr->nsdname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid NS data");
	}

	return store_record(type, name, ttl, rr);
}

static char* ns_human(void *rrv)
{
    struct rr_ns *rr = rrv;

    return rr->nsdname;
}

static void* ns_wirerdata(void *rrv)
{
    struct rr_ns *rr = rrv;

    return NULL;
}

struct rr_methods ns_methods = { ns_parse, ns_human, ns_wirerdata };
