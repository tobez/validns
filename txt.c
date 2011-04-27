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
	struct rr_txt *rr;
	struct binary_data txt[20];
	int i;

	i = 0;
	while (*s) {
		if (i >= 20)
			return bitch("program limit: too many text segments");
		txt[i] = extract_text(&s, "text segment");
		if (txt[i].length < 0)
			return NULL;
		if (txt[i].length > 255)
			return bitch("TXT segment too long");
		i++;
	}
	if (i == 0)
		return bitch("empty text record");

   	rr = getmem(sizeof(*rr) + sizeof(struct binary_data) * (i-1));
	rr->count = i;
	for (i = 0; i < rr->count; i++) {
		rr->txt[i] = txt[i];
	}

	return store_record(type, name, ttl, rr);
}

static char* txt_human(struct rr *rrv)
{
    struct rr_txt *rr = (struct rr_txt *)rrv;
    char ss[1024];
	int i;
	char *s = ss;
	int l;

	for (i = 0; i < rr->count; i++) {
		l = snprintf(s, 1024-(s-ss), "\"%s\" ", rr->txt[i].data);
		s += l;
	}
    return quickstrdup_temp(ss);
}

static struct binary_data txt_wirerdata(struct rr *rrv)
{
    struct rr_txt *rr = (struct rr_txt *)rrv;
	struct binary_data r, t;
	int i;

	r = bad_binary_data();
	t.length = 0;
	t.data = NULL;
	for (i = 0; i < rr->count; i++) {
		r = compose_binary_data("db", 1, t, rr->txt[i]);
		t = r;
	}
    return r;
}

struct rr_methods txt_methods = { txt_parse, txt_human, txt_wirerdata, NULL, NULL };
