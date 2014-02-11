/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <ctype.h>
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr *naptr_parse(char *name, long ttl, int type, char *s)
{
	struct rr_naptr *rr = getmem(sizeof(*rr));
	int i;
	struct binary_data text;

	i = extract_integer(&s, "order");
	if (i < 0)
		return NULL;
	if (i >= 65536)
		return bitch("order range is not valid");
	rr->order = i;

	i = extract_integer(&s, "preference");
	if (i < 0)
		return NULL;
	if (i >= 65536)
		return bitch("preference range is not valid");
	rr->preference = i;

	text = extract_text(&s, "flags");
	if (text.length < 0)
		return NULL;
	for (i = 0; i < text.length; i++) {
		if (!isalnum(text.data[i])) {
			return bitch("flags contains illegal characters");
		}
	}
	rr->flags = text;

	text = extract_text(&s, "services");
	if (text.length < 0)
		return NULL;
	rr->services = text;

	text = extract_text(&s, "regexp");
	if (text.length < 0)
		return NULL;
	rr->regexp = text;

	rr->replacement = extract_name(&s, "replacement", 0);
	if (!rr->replacement)
		return NULL;

	if (*s) {
		return bitch("garbage after valid NAPTR data");
	}

	return store_record(type, name, ttl, rr);
}

static char* naptr_human(struct rr *rrv)
{
	RRCAST(naptr);
    char s[1024];

	snprintf(s, 1024, "%hu %hu \"%s\" ...",
			 rr->order, rr->preference, rr->flags.data);

	return quickstrdup_temp(s);
}

static struct binary_data naptr_wirerdata(struct rr *rrv)
{
	RRCAST(naptr);

    return compose_binary_data("22bbbd", 1,
		rr->order, rr->preference,
		rr->flags, rr->services, rr->regexp,
		name2wire_name(rr->replacement));
}

struct rr_methods naptr_methods = { naptr_parse, naptr_human, naptr_wirerdata, NULL, NULL };
