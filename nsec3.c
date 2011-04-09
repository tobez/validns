/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */

#include <ctype.h>

#include "common.h"
#include "rr.h"

static struct rr* nsec3_parse(char *name, long ttl, int type, char *s)
{
    struct rr_nsec3 *rr = getmem(sizeof(*rr));
	int i;

	i = extract_integer(&s, "hash algorithm");
	if (i < 0)
		return NULL;
	if (i > 255)
		return bitch("bad hash algorithm value");
	if (i != 1)
		return bitch("unrecognized or unsupported hash algorithm");
	rr->hash_algorithm = i;

	i = extract_integer(&s, "flags");
	if (i < 0)
		return NULL;
	if (i > 255)
		return bitch("bad flags value");
	if (i != 0)
		return bitch("flags is supposed to be 0 for NSEC3");
	rr->flags = i;

	i = extract_integer(&s, "iterations");
	if (i < 0)
		return NULL;
	if (i > 2500)
		return bitch("bad iterations value");
	rr->iterations = i;
	/* TODO validate iteration count according to key size,
	 * as per http://tools.ietf.org/html/rfc5155#section-10.3 */

	if (*s == '-') {
		rr->salt.length = 0;
		rr->salt.data = NULL;
		s++;
		if (*s && !isspace(*s) && *s != ';' && *s != ')')
			return bitch("salt is not valid");
		s = skip_white_space(s);
	} else {
		rr->salt = extract_hex_binary_data(&s, "salt");
		if (rr->salt.length <= 0)
			return NULL;
		if (rr->salt.length > 255)
			return bitch("salt is too long");
	}
	if (*s) {
		return bitch("garbage after valid NSEC3 data");
	}

    return store_record(type, name, ttl, rr);
}

static char* nsec3_human(void *rrv)
{
    struct rr_nsec3 *rr = rrv;
    char ss[1024];
	char *s = ss;
	int l;
	char *base;
	int i, k;
	int type;
	char *type_name;

    l = snprintf(s, 1024, "%u %u %u ", rr->hash_algorithm, rr->flags, rr->iterations);
	s += l;
	if (rr->salt.length) {
		for (i = 0; i < rr->salt.length; i++) {
			l = snprintf(s, 1024-(s-ss), "%02X", (unsigned char)rr->salt.data[i]);
			s += l;
		}
	} else {
		sprintf(s, "-");
	}
    return quickstrdup_temp(ss);
}

static void* nsec3_wirerdata(void *rrv)
{
    struct rr_nsec3 *rr = rrv;

    return NULL;
}

struct rr_methods nsec3_methods = { nsec3_parse, nsec3_human, nsec3_wirerdata };
