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

static struct rr *mx_parse(char *name, long ttl, int type, char *s)
{
	struct rr_mx *rr = getmem(sizeof(*rr));

	rr->preference = extract_integer(&s, "MX preference");
	if (rr->preference < 0)
		return NULL;
	/* XXX preference range check */
	rr->exchange = extract_name(&s, "MX exchange", 0);
	if (!rr->exchange)
		return NULL;
	if (*s) {
		return bitch("garbage after valid MX data");
	}

	return store_record(type, name, ttl, rr);
}

static char* mx_human(struct rr *rrv)
{
	RRCAST(mx);
    char s[1024];

    snprintf(s, 1024, "%d %s",
	     rr->preference, rr->exchange);
    return quickstrdup_temp(s);
}

static struct binary_data mx_wirerdata(struct rr *rrv)
{
	RRCAST(mx);

    return compose_binary_data("2d", 1,
		rr->preference, name2wire_name(rr->exchange));
}

static void *mx_validate(struct rr *rrv)
{
	RRCAST(mx);

	if (G.opt.policy_checks[POLICY_MX_ALIAS]) {
		if (find_rr_set(T_CNAME, rr->exchange)) {
			return moan(rr->rr.file_name, rr->rr.line, "MX exchange is an alias");
		}
	}
	return NULL;
}

struct rr_methods mx_methods = { mx_parse, mx_human, mx_wirerdata, NULL, mx_validate };
