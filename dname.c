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

/* DNAMEs are described in http://tools.ietf.org/html/rfc2672 */

static struct rr *dname_parse(char *name, long ttl, int type, char *s)
{
	struct rr_dname *rr = getmem(sizeof(*rr));

	rr->target = extract_name(&s, "dname target");
	if (!rr->target)
		return NULL;
	if (*s) {
		return bitch("garbage after valid DNAME data");
	}

	return store_record(type, name, ttl, rr);
}

static char* dname_human(struct rr *rrv)
{
	RRCAST(dname);
    return rr->target;
}

static struct binary_data dname_wirerdata(struct rr *rrv)
{
	RRCAST(dname);
	return name2wire_name(rr->target);
}

static void* dname_validate_set(struct rr_set *rr_set)
{
	struct rr *rr;
	struct rr_set *suspect;
	int count;
	struct named_rr *named_rr, *next_named_rr;

	if (G.opt.policy_checks[POLICY_DNAME]) {
		named_rr = rr_set->named_rr;
		rr = rr_set->tail;
		if (rr_set->count > 1)
			return moan(rr->file_name, rr->line, "multiple DNAMEs");
		/* This check is already handled by "CNAME and other data" in cname.c *
		another_set = find_rr_set_in_named_rr(named_rr, T_CNAME);
		if (another_set)
			return moan(rr->file_name, rr->line, "DNAME cannot co-exist with a CNAME");
		*/
		next_named_rr = find_next_named_rr(named_rr);
		/* handle http://tools.ietf.org/html/rfc5155#section-10.2 case */
		if (next_named_rr && next_named_rr->parent == named_rr && (named_rr->flags & NAME_FLAG_APEX)) {
			count = get_rr_set_count(next_named_rr);
			if (count > 0) {
				suspect = find_rr_set_in_named_rr(next_named_rr, T_RRSIG);
				if (suspect)	count--;
				suspect = find_rr_set_in_named_rr(next_named_rr, T_NSEC3);
				if (suspect)	count--;
				if (count == 0)
					next_named_rr = find_next_named_rr(next_named_rr);
			}
		}
		if (next_named_rr && next_named_rr->parent == named_rr)
			return moan(rr->file_name, rr->line,
						"DNAME must not have any children (but %s exists)",
						next_named_rr->name);
	}
	return NULL;
}

struct rr_methods dname_methods = { dname_parse, dname_human, dname_wirerdata, dname_validate_set, NULL };
