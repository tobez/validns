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

static struct rr *rt_parse(char *name, long ttl, int type, char *s)
{
    struct rr_rt *rr = getmem(sizeof(*rr));

    rr->preference = extract_integer(&s, "RT preference", NULL);
    if (rr->preference < 0)
        return NULL;

    rr->intermediate_host = extract_name(&s, "intermediate-host", 0);
    if (!rr->intermediate_host)
        return NULL;
    if (*s) {
        return bitch("garbage after valid RT data");
    }

    return store_record(type, name, ttl, rr);
}

static char* rt_human(struct rr *rrv)
{
    RRCAST(rt);
    char s[1024];

    snprintf(s, 1024, "%d %s",
         rr->preference, rr->intermediate_host);
    return quickstrdup_temp(s);
}

static struct binary_data rt_wirerdata(struct rr *rrv)
{
    RRCAST(rt);

    return compose_binary_data("2d", 1,
        rr->preference, name2wire_name(rr->intermediate_host));
}

struct rr_methods rt_methods = { rt_parse, rt_human, rt_wirerdata, NULL, NULL };
