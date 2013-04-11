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

static struct rr *minfo_parse(char *name, long ttl, int type, char *s)
{
	struct rr_minfo *rr = getmem(sizeof(*rr));

	rr->rmailbx = extract_name(&s, "rmailbx", 0);
	if (!rr->rmailbx)
		return NULL;

	rr->emailbx = extract_name(&s, "emailbx", 0);
	if (!rr->emailbx)
		return NULL;

	if (*s) {
		return bitch("garbage after valid MINFO data");
	}

	return store_record(type, name, ttl, rr);
}

static char* minfo_human(struct rr *rrv)
{
	RRCAST(minfo);
	char s[1024];

	snprintf(s, 1024, "%s %s", rr->rmailbx, rr->emailbx);
	return quickstrdup_temp(s);
}

static struct binary_data minfo_wirerdata(struct rr *rrv)
{
	RRCAST(minfo);
	return compose_binary_data("dd", 1,
		name2wire_name(rr->rmailbx),
		name2wire_name(rr->emailbx));
}

struct rr_methods minfo_methods = { minfo_parse, minfo_human, minfo_wirerdata, NULL, NULL };
