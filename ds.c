/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
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

static struct rr* ds_parse(char *name, long ttl, int type, char *s)
{
	struct rr_ds *rr = getmem(sizeof(*rr));
	int key_tag, algorithm, digest_type;

	key_tag = extract_integer(&s, "key tag");
	if (key_tag < 0)	return NULL;
	rr->key_tag = key_tag;

	algorithm = extract_integer(&s, "algorithm");
	if (algorithm < 0)	return NULL;
	if (algorithm != 3 && algorithm != 5 &&
		algorithm != 8 && algorithm != 10)
	{
		return bitch("bad or unsupported algorithm %d", algorithm);
	}
	rr->algorithm = algorithm;

	digest_type = extract_integer(&s, "digest type");
	if (digest_type < 0)	return NULL;
	if (digest_type != 1) {
		return bitch("bad or unsupported digest type %d", digest_type);
	}
	rr->digest_type = digest_type;

	rr->digest = extract_hex_binary_data(&s, "digest", EXTRACT_EAT_WHITESPACE);
	if (rr->digest.length < 0)	return NULL;
	if (rr->digest.length != 20) {
		return bitch("wrong digest length: %d bytes found, %d bytes expected", rr->digest.length, 20);
	}

	if (*s) {
		return bitch("garbage after valid DS data");
	}
	return store_record(type, name, ttl, rr);
}

static char* ds_human(struct rr *rrv)
{
    struct rr_ds *rr = (struct rr_ds *)rrv;
    char ss[4096];
	char *s = ss;
	int l;
	int i;

    l = snprintf(s, 4096, "%u %u %u ", rr->key_tag, rr->algorithm, rr->digest_type);
	s += l;
	for (i = 0; i < rr->digest.length; i++) {
		l = snprintf(s, 4096-(s-ss), "%02X", (unsigned char)rr->digest.data[i]);
		s += l;
	}
    return quickstrdup_temp(ss);
}

static struct binary_data ds_wirerdata(struct rr *rrv)
{
    struct rr_ds *rr = (struct rr_ds *)rrv;

	return compose_binary_data("211d", 1,
		rr->key_tag, rr->algorithm, rr->digest_type,
		rr->digest);
}

struct rr_methods ds_methods = { ds_parse, ds_human, ds_wirerdata, NULL, NULL };