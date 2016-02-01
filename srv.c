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

static struct rr *srv_parse(char *name, long ttl, int type, char *s)
{
	struct rr_srv *rr = getmem(sizeof(*rr));
	int i;

	/* TODO validate `name` (underscores etc) http://tools.ietf.org/html/rfc2782 */

	i = extract_integer(&s, "priority", NULL);
	if (i < 0)
		return NULL;
	if (i >= 65536)
		return bitch("priority range is not valid");
	rr->priority = i;

	i = extract_integer(&s, "weight", NULL);
	if (i < 0)
		return NULL;
	if (i >= 65536)
		return bitch("weight range is not valid");
	rr->weight = i;

	i = extract_integer(&s, "port", NULL);
	if (i < 0)
		return NULL;
	if (i >= 65536)
		return bitch("port range is not valid");
	rr->port = i;

	rr->target = extract_name(&s, "target", 0);
	if (!rr->target)
		return NULL;

	if (*s) {
		return bitch("garbage after valid SRV data");
	}

	return store_record(type, name, ttl, rr);
}

static char* srv_human(struct rr *rrv)
{
	RRCAST(srv);
    char s[1024];

	snprintf(s, 1024, "%hu %hu %hu %s",
			 rr->priority, rr->weight, rr->port, rr->target);

	return quickstrdup_temp(s);
}

static struct binary_data srv_wirerdata(struct rr *rrv)
{
	RRCAST(srv);
    return compose_binary_data("222d", 1,
		rr->priority, rr->weight, rr->port,
		name2wire_name(rr->target));
}

struct rr_methods srv_methods = { srv_parse, srv_human, srv_wirerdata, NULL, NULL };
