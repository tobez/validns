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

static void *cname_parse(char *name, long ttl, int type, char *s)
{
	struct rr_cname *rr = getmem(sizeof(*rr));

	rr->cname = extract_name(&s, "cname");
	if (!rr->cname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid CNAME data");
	}

	return store_record(type, name, ttl, rr);
}

static char* cname_human(void *rrv)
{
    struct rr_cname *rr = rrv;
    return rr->cname;
}

static void* cname_wirerdata(void *rrv)
{
    struct rr_cname *rr = rrv;

    return NULL;
}

struct rr_methods cname_methods = { cname_parse, cname_human, cname_wirerdata };
