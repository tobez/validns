/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr *rp_parse(char *name, long ttl, int type, char *s)
{
	struct rr_rp *rr = getmem(sizeof(*rr));

	rr->mbox_dname = extract_name(&s, "mbox domain name", 0);
	if (!rr->mbox_dname)
		return NULL;

	rr->txt_dname = extract_name(&s, "txt domain name", 0);
	if (!rr->txt_dname)
		return NULL;

	if (*s) {
		return bitch("garbage after valid RP data");
	}

	return store_record(type, name, ttl, rr);
}

static char* rp_human(struct rr *rrv)
{
	RRCAST(rp);
    char s[1024];

    snprintf(s, 1024, "\"%s\" \"%s\"", rr->mbox_dname, rr->txt_dname);
    return quickstrdup_temp(s);
}

static struct binary_data rp_wirerdata(struct rr *rrv)
{
	RRCAST(rp);

	return compose_binary_data("dd", 1,
		name2wire_name(rr->mbox_dname),
		name2wire_name(rr->txt_dname));
}

static void *rp_validate(struct rr *rrv)
{
	RRCAST(rp);

	if (G.opt.policy_checks[POLICY_RP_TXT_EXISTS]) {
		if (name_belongs_to_zone(rr->txt_dname) && !find_rr_set(T_TXT, rr->txt_dname)) {
			return moan(rr->rr.file_name, rr->rr.line, "%s RP TXT %s does not exist",
				rr->rr.rr_set->named_rr->name, rr->txt_dname);
		}
	}
	return NULL;
}

struct rr_methods rp_methods = { rp_parse, rp_human, rp_wirerdata, NULL, rp_validate };

