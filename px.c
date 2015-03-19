/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
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

static struct rr *px_parse(char *name, long ttl, int type, char *s)
{
	struct rr_px *rr = getmem(sizeof(*rr));

	rr->preference = extract_integer(&s, "PX preference");
	if (rr->preference < 0)
		return NULL;

	rr->map822 = extract_name(&s, "map822", 0);
	if (!rr->map822)
		return NULL;

	rr->mapx400 = extract_name(&s, "mapx400", 0);
	if (!rr->mapx400)
		return NULL;

	if (*s) {
		return bitch("garbage after valid KX data");
	}

	return store_record(type, name, ttl, rr);
}

static char* px_human(struct rr *rrv)
{
	RRCAST(px);
    char s[1024];

    snprintf(s, 1024, "%d %s %s",
	     rr->preference, rr->map822, rr->mapx400);
    return quickstrdup_temp(s);
}

static struct binary_data px_wirerdata(struct rr *rrv)
{
	RRCAST(px);

    return compose_binary_data("2dd", 1,
		rr->preference,
		name2wire_name(rr->map822),
		name2wire_name(rr->mapx400));
}

struct rr_methods px_methods = { px_parse, px_human, px_wirerdata, NULL, NULL };
