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

static struct rr *mb_parse(char *name, long ttl, int type, char *s)
{
	struct rr_mb *rr = getmem(sizeof(*rr));

	rr->madname = extract_name(&s, "madname", 0);
	if (!rr->madname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid MB data");
	}

	return store_record(type, name, ttl, rr);
}

static char* mb_human(struct rr *rrv)
{
	RRCAST(mb);
    return rr->madname;
}

static struct binary_data mb_wirerdata(struct rr *rrv)
{
	RRCAST(mb);
	return name2wire_name(rr->madname);
}

struct rr_methods mb_methods = { mb_parse, mb_human, mb_wirerdata, NULL, NULL };
