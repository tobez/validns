/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2017 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr* caa_parse(char *name, long ttl, int type, char *s)
{
    struct rr_caa *rr = getmem(sizeof(*rr));
    int flags;
    char *str_tag;

    flags = extract_integer(&s, "CAA flags", NULL);
    if (flags < 0)  return NULL;
    if (flags != 0 && flags != 128)
        return bitch("CAA unrecognized flags value");
    rr->flags = flags;

    str_tag = extract_label(&s, "CAA tag", "temporary");
    if (!str_tag) return NULL;

    if (strcmp(str_tag, "issue") == 0) {
        /* ok */
    } else if (strcmp(str_tag, "issuewild") == 0) {
        /* ok */
    } else if (strcmp(str_tag, "iodef") == 0) {
        /* ok */
    } else if (strcmp(str_tag, "auth") == 0)
        return bitch("CAA reserved tag name");
    else if (strcmp(str_tag, "path") == 0)
        return bitch("CAA reserved tag name");
    else if (strcmp(str_tag, "policy") == 0)
        return bitch("CAA reserved tag name");
    else
        return bitch("CAA unrecognized tag name");

    rr->tag = compose_binary_data("s", 0, str_tag);
    rr->value = extract_text(&s, "CAA tag value");
    if (rr->value.length <= 0)
        return bitch("CAA missing tag value");

    if (*s) {
        return bitch("garbage after valid CAA data");
    }
    return store_record(type, name, ttl, rr);
}

static char* caa_human(struct rr *rrv)
{
    RRCAST(caa);
    char ss[4096];
    char *s = ss;
    int l;

    /* incomplete */
    l = snprintf(s, 4096, "%u", rr->flags);
    s += l;
    return quickstrdup_temp(ss);
}

static struct binary_data caa_wirerdata(struct rr *rrv)
{
    RRCAST(caa);

    return compose_binary_data("1dd", 1, rr->flags, rr->tag, rr->value);
}

/*
static void *caa_validate(struct rr *rrv)
{
    dump_binary_data(stderr, call_get_wired(rrv));
    return NULL;
}
*/

struct rr_methods caa_methods = { caa_parse, caa_human, caa_wirerdata, NULL, NULL };
