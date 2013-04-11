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

static struct rr* nsap_parse(char *name, long ttl, int type, char *s)
{
	struct rr_nsap *rr = getmem(sizeof(*rr));

	rr->data = extract_hex_binary_data(&s, "NSAP data", EXTRACT_EAT_WHITESPACE);
	if (rr->data.length < 0)	return NULL;

	if (*s) {
		return bitch("garbage after valid NSAP data");
	}
	return store_record(type, name, ttl, rr);
}

static char* nsap_human(struct rr *rrv)
{
    return "...";
}

static struct binary_data nsap_wirerdata(struct rr *rrv)
{
	RRCAST(nsap);

	return compose_binary_data("d", 1, rr->data);
}

struct rr_methods nsap_methods = { nsap_parse, nsap_human, nsap_wirerdata, NULL, NULL };
