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
	struct rr *ret_rr;

	rr->nsdname = extract_name(&s, "name server domain name");
	if (!rr->nsdname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid NS data");
	}

	ret_rr = store_record(type, name, ttl, rr);
	if (ret_rr) {
		if (!(ret_rr->rr_set->named_rr->flags & (NAME_FLAG_APEX|NAME_FLAG_DELEGATION))) {
			ret_rr->rr_set->named_rr->flags |= NAME_FLAG_DELEGATION;
			G.stats.delegations++;
		}
	}
	return ret_rr;
}

static char* ns_human(struct rr *rrv)
{
	RRCAST(ns);

    return rr->nsdname;
}

static struct binary_data ns_wirerdata(struct rr *rrv)
{
	RRCAST(ns);
	return name2wire_name(rr->nsdname);
}

static void* ns_validate_set(struct rr_set *rr_set)
{
	struct rr *rr;
	if (G.opt.policy_checks[POLICY_SINGLE_NS]) {
		if (rr_set->count < 2) {
			rr = rr_set->tail;
			return moan(rr->file_name, rr->line, "there should be at least two NS records per name");
		}
	}
	return NULL;
}

static void *ns_validate(struct rr *rrv)
{
	RRCAST(ns);

	if (G.opt.policy_checks[POLICY_NS_ALIAS]) {
		if (find_rr_set(T_CNAME, rr->nsdname)) {
			return moan(rr->rr.file_name, rr->rr.line, "NS data is an alias");
		}
	}
	return NULL;
}

struct rr_methods ns_methods = { ns_parse, ns_human, ns_wirerdata, ns_validate_set, ns_validate };
