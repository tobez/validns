/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

/* XXX Does not accept multiple character-strings */

static struct rr *txt_parse(char *name, long ttl, int type, char *s)
{
    struct rr_txt *rr;
    struct binary_data txt;
    struct rr_txt_segment *first = NULL;
    struct rr_txt_segment *last  = NULL;
    struct rr_txt_segment *cur   = NULL;
    int i;

    i = 0;
    while (*s) {
        freeall_temp();
        txt = extract_text(&s, "text segment");
        if (txt.length < 0)
            return NULL;
        if (txt.length > 255)
            return bitch("TXT segment too long");
        i++;
        cur = getmem(sizeof(*cur));
        cur->txt = txt;
        cur->next = NULL;
        if (!first)
            first = cur;
        if (last)
            last->next = cur;
        last = cur;
    }
    if (i == 0)
        return bitch("empty text record");

    rr = getmem(sizeof(*rr));
    rr->count = i;
    rr->txt = first;

    return store_record(type, name, ttl, rr);
}

static char* txt_human(struct rr *rrv)
{
    RRCAST(txt);
    char ss[1024];
    char *s = ss;
    int l;
    struct rr_txt_segment *seg = rr->txt;

    while (seg) {
        /* XXX would be nice to escape " with \ in strings */
        l = snprintf(s, 1024-(s-ss), "\"%s\" ", seg->txt.data);
        s += l;
        seg = seg->next;
    }
    return quickstrdup_temp(ss);
}

static struct binary_data txt_wirerdata(struct rr *rrv)
{
    RRCAST(txt);
    struct binary_data r, t;
    struct rr_txt_segment *seg = rr->txt;

    r = bad_binary_data();
    t.length = 0;
    t.data = NULL;
    while (seg) {
        r = compose_binary_data("db", 1, t, seg->txt);
        t = r;
        seg = seg->next;
    }
    return r;
}

struct rr_methods txt_methods = { txt_parse, txt_human, txt_wirerdata, NULL, NULL };
