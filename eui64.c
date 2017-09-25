/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2016 Pieter Lexis <pieter.lexis@powerdns.com>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr* eui64_parse(char *name, long ttl, int type, char *s)
{
	struct rr_eui64 *rr = getmem(sizeof(*rr));
	uint8_t r[8];

	if (sscanf(s, "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx",
		r+0, r+1, r+2, r+3, r+4, r+5, r+6, r+7) != 8) {
		return bitch("%s: in wrong format", name);
	}

	memmove(rr->address, r, 8);

	return store_record(type, name, ttl, rr);
}

static struct binary_data eui64_wirerdata(struct rr *rrv)
{
	RRCAST(eui64);
	struct binary_data r;

	r.length = sizeof(rr->address);
	r.data = (void *)&rr->address;

	return r;
}

static char* eui64_human(struct rr *rrv)
{
  return "...";
}

struct rr_methods eui64_methods = { eui64_parse, eui64_human, eui64_wirerdata, NULL, NULL };

