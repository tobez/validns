/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2013 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

/* XXX Does not accept multiple character-strings */

static struct rr *isdn_parse(char *name, long ttl, int type, char *s)
{
	struct rr_isdn *rr = getmem(sizeof(*rr));

	rr->isdn_address = extract_text(&s, "ISDN-address");
	if (rr->isdn_address.length < 0)
		return NULL;
	if (rr->isdn_address.length > 255)
		return bitch("ISDN-address too long");

	rr->sa_present = 0;
	if (*s) {
		rr->sa = extract_text(&s, "subaddress");
		if (rr->sa.length < 0)
			return NULL;
		if (rr->sa.length > 255)
			return bitch("subaddress too long");
		rr->sa_present = 1;
	}

	if (*s) {
		return bitch("garbage after valid ISDN data");
	}

	return store_record(type, name, ttl, rr);
}

static char* isdn_human(struct rr *rrv)
{
	RRCAST(isdn);

    return rr->isdn_address.data;
}

static struct binary_data isdn_wirerdata(struct rr *rrv)
{
	RRCAST(isdn);
	struct binary_data r, t;

	r = bad_binary_data();
	t.length = 0;
	t.data = NULL;
	r = compose_binary_data("db", 1, t, rr->isdn_address);
	t = r;
	if (rr->sa_present) {
		r = compose_binary_data("db", 1, t, rr->sa);
		t = r;
	}
    return r;
}

struct rr_methods isdn_methods = { isdn_parse, isdn_human, isdn_wirerdata, NULL, NULL };
