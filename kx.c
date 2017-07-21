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

static struct rr *kx_parse(char *name, long ttl, int type, char *s)
{
    struct rr_kx *rr = getmem(sizeof(*rr));

    rr->preference = extract_integer(&s, "KX preference", NULL);
    if (rr->preference < 0)
        return NULL;

    rr->exchanger = extract_name(&s, "KX exchanger", 0);
    if (!rr->exchanger)
        return NULL;

    if (*s) {
        return bitch("garbage after valid KX data");
    }

    return store_record(type, name, ttl, rr);
}

static char* kx_human(struct rr *rrv)
{
    RRCAST(kx);
    char s[1024];

    snprintf(s, 1024, "%d %s",
         rr->preference, rr->exchanger);
    return quickstrdup_temp(s);
}

static struct binary_data kx_wirerdata(struct rr *rrv)
{
    RRCAST(kx);

    return compose_binary_data("2d", 1,
        rr->preference,
        name2wire_name(rr->exchanger));
}

struct rr_methods kx_methods = { kx_parse, kx_human, kx_wirerdata, NULL, NULL };
