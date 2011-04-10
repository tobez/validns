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

static struct rr *cname_parse(char *name, long ttl, int type, char *s)
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

static char* cname_human(struct rr *rrv)
{
    struct rr_cname *rr = (struct rr_cname *)rrv;
    return rr->cname;
}

static struct binary_data cname_wirerdata(struct rr *rrv)
{
	return bad_binary_data();
}

struct rr_methods cname_methods = { cname_parse, cname_human, cname_wirerdata, NULL, NULL };
