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

static struct rr *afsdb_parse(char *name, long ttl, int type, char *s)
{
    struct rr_afsdb *rr = getmem(sizeof(*rr));

    rr->subtype = extract_integer(&s, "AFSDB subtype", NULL);
    if (rr->subtype < 0)
        return NULL;

    if (rr->subtype != 1 && rr->subtype != 2)
        return bitch("unknown AFSDB subtype");

    rr->hostname = extract_name(&s, "AFSDB hostname", 0);
    if (!rr->hostname)
        return NULL;

    if (*s) {
        return bitch("garbage after valid AFSDB data");
    }

    return store_record(type, name, ttl, rr);
}

static char* afsdb_human(struct rr *rrv)
{
    RRCAST(afsdb);
    char s[1024];

    snprintf(s, 1024, "%d %s",
         rr->subtype, rr->hostname);
    return quickstrdup_temp(s);
}

static struct binary_data afsdb_wirerdata(struct rr *rrv)
{
    RRCAST(afsdb);

    return compose_binary_data("2d", 1,
        rr->subtype, name2wire_name(rr->hostname));
}

struct rr_methods afsdb_methods = { afsdb_parse, afsdb_human, afsdb_wirerdata, NULL, NULL };
