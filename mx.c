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

static void *mx_parse(char *name, long ttl, int type, char *s)
{
	struct rr_mx *rr = getmem(sizeof(*rr));

	rr->preference = extract_integer(&s, "MX preference");
	if (rr->preference < 0)
		return NULL;
	/* XXX preference range check */
	rr->exchange = extract_name(&s, "MX exchange");
	if (!rr->exchange)
		return NULL;
	if (*s) {
		return bitch("garbage after valid MX data");
	}

	return store_record(type, name, ttl, rr);
}

static char* mx_human(void *rrv)
{
    struct rr_mx *rr = rrv;
    char s[1024];

    snprintf(s, 1024, "%d %s",
	     rr->preference, rr->exchange);
    return quickstrdup_temp(s);
}

static void* mx_wirerdata(void *rrv)
{
    struct rr_mx *rr = rrv;

    return NULL;
}

struct rr_methods mx_methods = { mx_parse, mx_human, mx_wirerdata };
