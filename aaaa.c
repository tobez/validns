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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr *aaaa_parse(char *name, long ttl, int type, char *s)
{
	struct rr_aaaa *rr = getmem(sizeof(*rr));

	if (extract_ipv6(&s, "IPv6 address", &rr->address) <= 0)
		return NULL;
	if (*s) {
		return bitch("garbage after valid AAAA data");
	}

	return store_record(type, name, ttl, rr);
}

static char* aaaa_human(struct rr *rrv)
{
	RRCAST(aaaa);
    char s[1024];

	if (inet_ntop(AF_INET6, &rr->address, s, 1024))
		return quickstrdup_temp(s);
	return "????";
}

static struct binary_data aaaa_wirerdata(struct rr *rrv)
{
	RRCAST(aaaa);
	struct binary_data r;

	r.length = sizeof(rr->address);
	r.data = (void *)&rr->address;
	return r;
}

static void* aaaa_validate_set(struct rr_set *rr_set)
{
	if (rr_set->named_rr->flags & NAME_FLAG_CONTAINS_SLASH) {
		struct rr *rr = rr_set->tail;
		return moan(rr->file_name, rr->line, "host name contains '/'");
	}
	return NULL;
}

struct rr_methods aaaa_methods = { aaaa_parse, aaaa_human, aaaa_wirerdata, aaaa_validate_set, NULL };

