/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2013 Anton Berezin <tobez@tobez.org>
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

static struct rr *mr_parse(char *name, long ttl, int type, char *s)
{
	struct rr_mr *rr = getmem(sizeof(*rr));

	rr->newname = extract_name(&s, "newname", 0);
	if (!rr->newname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid MR data");
	}

	return store_record(type, name, ttl, rr);
}

static char* mr_human(struct rr *rrv)
{
	RRCAST(mr);
    return rr->newname;
}

static struct binary_data mr_wirerdata(struct rr *rrv)
{
	RRCAST(mr);
	return name2wire_name(rr->newname);
}

struct rr_methods mr_methods = { mr_parse, mr_human, mr_wirerdata, NULL, NULL };
