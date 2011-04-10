/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
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

static struct rr *mx_parse(char *name, long ttl, int type, char *s)
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

static char* mx_human(struct rr *rrv)
{
    struct rr_mx *rr = (struct rr_mx *)rrv;
    char s[1024];

    snprintf(s, 1024, "%d %s",
	     rr->preference, rr->exchange);
    return quickstrdup_temp(s);
}

static struct binary_data mx_wirerdata(struct rr *rrv)
{
    return bad_binary_data();
}

struct rr_methods mx_methods = { mx_parse, mx_human, mx_wirerdata, NULL, NULL };
