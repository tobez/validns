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

	algorithm = extract_algorithm(&s, "algorithm");
	if (algorithm == ALG_UNSUPPORTED)	return NULL;
	rr->algorithm = algorithm;

	digest_type = extract_integer(&s, "digest type");
	if (digest_type < 0)	return NULL;
	rr->digest_type = digest_type;

	rr->digest = extract_hex_binary_data(&s, "digest", EXTRACT_EAT_WHITESPACE);
	if (rr->digest.length < 0)	return NULL;

	/* See http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xml
	 * for valid digest types. */
	switch (digest_type) {
	case 1:
		if (rr->digest.length != SHA1_BYTES) {
			return bitch("wrong SHA-1 digest length: %d bytes found, %d bytes expected", rr->digest.length, SHA1_BYTES);
		}
		break;
	case 2:
		if (rr->digest.length != SHA256_BYTES) {
			return bitch("wrong SHA-256 digest length: %d bytes found, %d bytes expected", rr->digest.length, SHA256_BYTES);
		}
		break;
	case 3:
		if (rr->digest.length != GOST_BYTES) {
			return bitch("wrong GOST R 34.11-94 digest length: %d bytes found, %d bytes expected", rr->digest.length, GOST_BYTES);
		}
		break;
	default:
		return bitch("bad or unsupported digest type %d", digest_type);
	}

	if (*s) {
		return bitch("garbage after valid DS data");
	}
	return store_record(type, name, ttl, rr);
}

static char* ds_human(struct rr *rrv)
{
	RRCAST(ds);
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
	RRCAST(ds);

	return compose_binary_data("211d", 1,
		rr->key_tag, rr->algorithm, rr->digest_type,
		rr->digest);
}

struct rr_methods ds_methods = { ds_parse, ds_human, ds_wirerdata, NULL, NULL };
