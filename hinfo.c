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

static struct rr *hinfo_parse(char *name, long ttl, int type, char *s)
{
	struct rr_hinfo *rr = getmem(sizeof(*rr));

	rr->cpu = extract_text(&s, "CPU");
	if (rr->cpu.length < 0)
		return NULL;
	if (rr->cpu.length > 255)
		return bitch("CPU string is too long");

	rr->os = extract_text(&s, "OS");
	if (rr->os.length < 0)
		return NULL;
	if (rr->os.length > 255)
		return bitch("OS string is too long");

	if (*s) {
		return bitch("garbage after valid HINFO data");
	}

	return store_record(type, name, ttl, rr);
}

static char* hinfo_human(struct rr *rrv)
{
	RRCAST(hinfo);
    char s[1024];

    snprintf(s, 1024, "\"%s\" \"%s\"", rr->cpu.data, rr->os.data);
    return quickstrdup_temp(s);
}

static struct binary_data hinfo_wirerdata(struct rr *rrv)
{
	RRCAST(hinfo);

    return compose_binary_data("bb", 1, rr->cpu, rr->os);
}

struct rr_methods hinfo_methods = { hinfo_parse, hinfo_human, hinfo_wirerdata, NULL, NULL };
