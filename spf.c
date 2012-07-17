/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, 2012 Anton Berezin <tobez@tobez.org>
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

/* XXX
 * We need to add the following spf-specific policy checks:
 * 	- record not too long (DNS name + length of SPF+TXT < 450) - rfc4408, 3.1.4
 * 	- record should match /^v=spf1( |$)/  - rfc4408, 4.5
 * 	- maybe check for other syntax features
 * 	- there should be an identical TXT record - rfc4408, 3.1.1
 * 	- there should only be one SPF per DNS name - rfc4408, 4.5
 */

static struct rr *spf_parse(char *name, long ttl, int type, char *s)
{
	struct rr_spf *rr;
	struct binary_data spf[20];
	int i;

	i = 0;
	while (*s) {
		if (i >= 20)
			return bitch("program limit: too many SPF text segments");
		spf[i] = extract_text(&s, "SPF text segment");
		if (spf[i].length < 0)
			return NULL;
		if (spf[i].length > 255)
			return bitch("SPF segment too long");
		i++;
	}
	if (i == 0)
		return bitch("empty text record");

   	rr = getmem(sizeof(*rr) + sizeof(struct binary_data) * (i-1));
	rr->count = i;
	for (i = 0; i < rr->count; i++) {
		rr->spf[i] = spf[i];
	}

	return store_record(type, name, ttl, rr);
}

static char* spf_human(struct rr *rrv)
{
	RRCAST(spf);
    char ss[1024];
	int i;
	char *s = ss;
	int l;

	for (i = 0; i < rr->count; i++) {
		l = snprintf(s, 1024-(s-ss), "\"%s\" ", rr->spf[i].data);
		s += l;
	}
    return quickstrdup_temp(ss);
}

static struct binary_data spf_wirerdata(struct rr *rrv)
{
	RRCAST(spf);
	struct binary_data r, t;
	int i;

	r = bad_binary_data();
	t.length = 0;
	t.data = NULL;
	for (i = 0; i < rr->count; i++) {
		r = compose_binary_data("db", 1, t, rr->spf[i]);
		t = r;
	}
    return r;
}

struct rr_methods spf_methods = { spf_parse, spf_human, spf_wirerdata, NULL, NULL };
