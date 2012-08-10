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

static struct rr *l64_parse(char *name, long ttl, int type, char *s)
{
	struct rr_l64 *rr = getmem(sizeof(*rr));
	int preference;

	rr->preference = preference = extract_integer(&s, "L64 preference");
	if (preference < 0)
		return NULL;
	if (extract_u64(&s, "Locator64", &rr->locator64) < 0)
		return NULL;

	if (*s) {
		return bitch("garbage after valid L64 data");
	}

	return store_record(type, name, ttl, rr);
}

static char* l64_human(struct rr *rrv)
{
	RRCAST(l64);
    char s[1024];

    snprintf(s, 1024, "%d %x:%x:%x:%x",
	     rr->preference,
		 (unsigned)(rr->locator64 >> 48) & 0xffff,
		 (unsigned)(rr->locator64 >> 32) & 0xffff,
		 (unsigned)(rr->locator64 >> 16) & 0xffff,
		 (unsigned)(rr->locator64 >> 0) & 0xffff);
    return quickstrdup_temp(s);
}

static struct binary_data l64_wirerdata(struct rr *rrv)
{
	RRCAST(l64);
    return compose_binary_data("28", 1, rr->preference, rr->locator64);
}

struct rr_methods l64_methods = { l64_parse, l64_human, l64_wirerdata, NULL, NULL };
