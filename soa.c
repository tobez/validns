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

static void* soa_parse(char *name, long ttl, int type, char *s)
{
	struct rr_soa *rr = getmem(sizeof(*rr));

	rr->mname = extract_name(&s, "mname");
	if (!rr->mname) return NULL;
	rr->rname = extract_name(&s, "rname");
	if (!rr->rname) return NULL;
	rr->serial = extract_integer(&s, "serial");
	if (rr->serial < 0) return NULL;
	rr->refresh = extract_timevalue(&s, "refresh");
	if (rr->refresh < 0) return NULL;
	rr->retry = extract_timevalue(&s, "retry");
	if (rr->retry < 0) return NULL;
	rr->expire = extract_timevalue(&s, "expire");
	if (rr->expire < 0) return NULL;
	rr->minimum = extract_timevalue(&s, "minimum");
	if (rr->minimum < 0) return NULL;
	if (*s) {
		return bitch("garbage after valid SOA data");
	}
	return store_record(type, name, ttl, rr);
}

static char* soa_human(void *rrv)
{
    struct rr_soa *rr = rrv;
    char s[1024];

    snprintf(s, 1024, "%s %s %d %d %d %d %d",
	     rr->mname, rr->rname, rr->serial,
	     rr->refresh, rr->retry, rr->expire, rr->minimum);
    return quickstrdup_temp(s);
}

static void* soa_wirerdata(void *rrv)
{
    struct rr_soa *rr = rrv;

    return NULL;
}

struct rr_methods soa_methods = { soa_parse, soa_human, soa_wirerdata };
