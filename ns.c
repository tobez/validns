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

static struct rr *ns_parse(char *name, long ttl, int type, char *s)
{
	struct rr_ns *rr = getmem(sizeof(*rr));

	rr->nsdname = extract_name(&s, "nsdname");
	if (!rr->nsdname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid NS data");
	}

	return store_record(type, name, ttl, rr);
}

static char* ns_human(struct rr *rrv)
{
    struct rr_ns *rr = (struct rr_ns *)rrv;

    return rr->nsdname;
}

static struct binary_data ns_wirerdata(struct rr *rrv)
{
    struct rr_ns *rr = (struct rr_ns *)rrv;
	return name2wire_name(rr->nsdname);
}

static void* ns_validate_set(struct rr_set *rr_set)
{
	struct rr *rr;
	if (G.opt.policy_checks) {
		if (rr_set->count < 2) {
			rr = rr_set->tail;
			return moan(rr->file_name, rr->line, "there should be at least two NS records per name");
		}
	}
	return NULL;
}

struct rr_methods ns_methods = { ns_parse, ns_human, ns_wirerdata, ns_validate_set, NULL };
