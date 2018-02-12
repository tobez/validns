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

static struct rr *cname_parse(char *name, long ttl, int type, char *s)
{
    struct rr_cname *rr = getmem(sizeof(*rr));

    rr->cname = extract_name(&s, "cname", 0);
    if (!rr->cname)
        return NULL;
    if (*s) {
        return bitch("garbage after valid CNAME data");
    }

    return store_record(type, name, ttl, rr);
}

static char* cname_human(struct rr *rrv)
{
    RRCAST(cname);
    return rr->cname;
}

static struct binary_data cname_wirerdata(struct rr *rrv)
{
    RRCAST(cname);
    return name2wire_name(rr->cname);
}

static void* cname_validate_set(struct rr_set *rr_set)
{
    struct rr *rr;
    struct rr_set *another_set;
    struct named_rr *named_rr;
    int count;

    if (G.opt.policy_checks[POLICY_CNAME_OTHER_DATA]) {
        if (rr_set->count > 1) {
            rr = rr_set->tail;
            return moan(rr->file_name, rr->line, "CNAME and other data");
        }
        named_rr = rr_set->named_rr;
        count = get_rr_set_count(named_rr);
        if (count > 1) {
            another_set = find_rr_set_in_named_rr(named_rr, T_RRSIG);
            if (another_set)
                count -= another_set->count;
            another_set = find_rr_set_in_named_rr(named_rr, T_NSEC);
            if (another_set)
                count -= another_set->count;
            if (count > 1) {
                rr = rr_set->tail;
                return moan(rr->file_name, rr->line, "CNAME and other data");
            }
        }
    }
    return NULL;
}

struct rr_methods cname_methods = { cname_parse, cname_human, cname_wirerdata, cname_validate_set, NULL };
