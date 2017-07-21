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

static struct rr *nid_parse(char *name, long ttl, int type, char *s)
{
    struct rr_nid *rr = getmem(sizeof(*rr));
    int preference;

    rr->preference = preference = extract_integer(&s, "NID preference", NULL);
    if (preference < 0)
        return NULL;
    if (extract_u64(&s, "NodeID", &rr->node_id) < 0)
        return NULL;

    if (*s) {
        return bitch("garbage after valid NID data");
    }

    return store_record(type, name, ttl, rr);
}

static char* nid_human(struct rr *rrv)
{
    RRCAST(nid);
    char s[1024];

    snprintf(s, 1024, "%d %x:%x:%x:%x",
         rr->preference,
         (unsigned)(rr->node_id >> 48) & 0xffff,
         (unsigned)(rr->node_id >> 32) & 0xffff,
         (unsigned)(rr->node_id >> 16) & 0xffff,
         (unsigned)(rr->node_id >> 0) & 0xffff);
    return quickstrdup_temp(s);
}

static struct binary_data nid_wirerdata(struct rr *rrv)
{
    RRCAST(nid);
    return compose_binary_data("28", 1, rr->preference, rr->node_id);
}

struct rr_methods nid_methods = { nid_parse, nid_human, nid_wirerdata, NULL, NULL };
