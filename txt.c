/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
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
	struct rr_txt *rr = getmem(sizeof(*rr));
	struct binary_data txt;

	txt = extract_text(&s, "text");
	if (txt.length < 0)
		return NULL;
	if (txt.length > 255)
		return bitch("TXT segment too long");
	if (*s) {
		return bitch("garbage after valid TXT data");
	}
	rr->txt = txt;

	return store_record(type, name, ttl, rr);
}

static char* txt_human(struct rr *rrv)
{
    struct rr_txt *rr = (struct rr_txt *)rrv;
    char s[1024];

    snprintf(s, 1024, "\"%s\"", rr->txt.data);
    return quickstrdup_temp(s);
}

static struct binary_data txt_wirerdata(struct rr *rrv)
{
    struct rr_txt *rr = (struct rr_txt *)rrv;

    return compose_binary_data("b", 1, rr->txt);
}

struct rr_methods txt_methods = { txt_parse, txt_human, txt_wirerdata, NULL, NULL };
