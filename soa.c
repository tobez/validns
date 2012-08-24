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
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr* soa_parse(char *name, long ttl, int type, char *s)
{
	struct rr_soa *rr = getmem(sizeof(*rr));
	long long i;

	rr->mname = extract_name(&s, "mname", 0);
	if (!rr->mname) return NULL;
	rr->rname = extract_name(&s, "rname", 0);
	if (!rr->rname) return NULL;
	i = extract_integer(&s, "serial");
	if (i < 0) return NULL;
	if (i > 4294967295UL) return bitch("serial is out of range");
	rr->serial = i;
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

static char* soa_human(struct rr *rrv)
{
	RRCAST(soa);
    char s[1024];

    snprintf(s, 1024, "%s %s %u %d %d %d %d",
	     rr->mname, rr->rname, rr->serial,
	     rr->refresh, rr->retry, rr->expire, rr->minimum);
    return quickstrdup_temp(s);
}

static struct binary_data soa_wirerdata(struct rr *rrv)
{
	RRCAST(soa);

	return compose_binary_data("dd44444", 1,
		name2wire_name(rr->mname), name2wire_name(rr->rname),
		rr->serial, rr->refresh, rr->retry,
		rr->expire, rr->minimum);
}

struct rr_methods soa_methods = { soa_parse, soa_human, soa_wirerdata, NULL, NULL };
