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

static struct rr *l32_parse(char *name, long ttl, int type, char *s)
{
	struct rr_l32 *rr = getmem(sizeof(*rr));
	struct in_addr ipv4_like;
	int preference;

	rr->preference = preference = extract_integer(&s, "L32 preference");
	if (preference < 0)
		return NULL;
	if (extract_ipv4(&s, "Locator32", &ipv4_like) <= 0)
		return NULL;
	rr->locator32 = ipv4_like.s_addr;

	if (*s) {
		return bitch("garbage after valid L32 data");
	}

	return store_record(type, name, ttl, rr);
}

static char* l32_human(struct rr *rrv)
{
	RRCAST(l32);
    char s[1024];

    snprintf(s, 1024, "%d %d.%d.%d.%d",
	     rr->preference,
		 (rr->locator32 >> 24) & 0xff,
		 (rr->locator32 >> 16) & 0xff,
		 (rr->locator32 >> 8) & 0xff,
		 (rr->locator32 >> 0) & 0xff);
    return quickstrdup_temp(s);
}

static struct binary_data l32_wirerdata(struct rr *rrv)
{
	RRCAST(l32);
    return compose_binary_data("24", 1, rr->preference, rr->locator32);
}

struct rr_methods l32_methods = { l32_parse, l32_human, l32_wirerdata, NULL, NULL };
