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

static struct rr *mg_parse(char *name, long ttl, int type, char *s)
{
	struct rr_mg *rr = getmem(sizeof(*rr));

	rr->mgmname = extract_name(&s, "mgmname", 0);
	if (!rr->mgmname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid MG data");
	}

	return store_record(type, name, ttl, rr);
}

static char* mg_human(struct rr *rrv)
{
	RRCAST(mg);
    return rr->mgmname;
}

static struct binary_data mg_wirerdata(struct rr *rrv)
{
	RRCAST(mg);
	return name2wire_name(rr->mgmname);
}

struct rr_methods mg_methods = { mg_parse, mg_human, mg_wirerdata, NULL, NULL };
