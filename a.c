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

static struct rr *a_parse(char *name, long ttl, int type, char *s)
{
    struct rr_a *rr = getmem(sizeof(*rr));

    if (extract_ipv4(&s, "IPv4 address", &rr->address) <= 0)
        return NULL;
    if (*s) {
        return bitch("garbage after valid A data");
    }

    return store_record(type, name, ttl, rr);
}

static char* a_human(struct rr *rrv)
{
    RRCAST(a);
    char s[1024];

    if (inet_ntop(AF_INET, &rr->address, s, 1024))
        return quickstrdup_temp(s);
    return "????";
}

static struct binary_data a_wirerdata(struct rr *rrv)
{
    RRCAST(a);
    struct binary_data r;

    r.length = sizeof(rr->address);
    r.data = (void *)&rr->address;
    return r;
}

static void* a_validate_set(struct rr_set *rr_set)
{
    if (rr_set->named_rr->flags & NAME_FLAG_CONTAINS_SLASH) {
        struct rr *rr = rr_set->tail;
        return moan(rr->file_name, rr->line, "host name contains '/'");
    }
    return NULL;
}

struct rr_methods a_methods = { a_parse, a_human, a_wirerdata, a_validate_set, NULL };
