/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "common.h"
#include "rr.h"

static struct rr *txt_parse(char *name, long ttl, int type, char *s)
{
	struct rr_txt *rr = getmem(sizeof(*rr));
	struct binary_data txt;

	txt = extract_text(&s, "text");
	if (txt.length < 0)
		return NULL;
	if (*s) {
		return bitch("garbage after valid TXT data");
	}
	rr->length = txt.length;
	rr->txt = txt.data;

	return store_record(type, name, ttl, rr);
}

static char* txt_human(struct rr *rrv)
{
    struct rr_txt *rr = (struct rr_txt *)rrv;
    char s[1024];

    snprintf(s, 1024, "\"%s\"", rr->txt);
    return quickstrdup_temp(s);
}

static struct binary_data txt_wirerdata(struct rr *rrv)
{
    return bad_binary_data();
}

struct rr_methods txt_methods = { txt_parse, txt_human, txt_wirerdata, NULL, NULL };
