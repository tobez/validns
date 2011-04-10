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

static struct rr *a_parse(char *name, long ttl, int type, char *s)
{
    struct rr_a *rr = getmem(sizeof(*rr));

    rr->address = extract_ip(&s, "ip address");
    if (!rr->address)
	return NULL;
    if (*s) {
	return bitch("garbage after valid A data");
    }

    return store_record(type, name, ttl, rr);
}

static char* a_human(struct rr *rrv)
{
    struct rr_a *rr = (struct rr_a *)rrv;
    char s[1024];

    snprintf(s, 1024, "%d.%d.%d.%d",
			 0xff & (rr->address >> 24), 0xff & (rr->address >> 16),
			 0xff & (rr->address >> 8), 0xff & rr->address);
    return quickstrdup_temp(s);
}

static struct binary_data a_wirerdata(struct rr *rrv)
{
    return bad_binary_data();
}

struct rr_methods a_methods = { a_parse, a_human, a_wirerdata, NULL, NULL };
