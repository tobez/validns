/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
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

static struct rr* nsec3param_parse(char *name, long ttl, int type, char *s)
{
    struct rr_nsec3param *rr = getmem(sizeof(*rr));
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
		return bitch("flags is supposed to be 0 for NSEC3PARAM");
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
		return bitch("garbage after valid NSEC3PARAM data");
	}

    return store_record(type, name, ttl, rr);
}

static char* nsec3param_human(struct rr *rrv)
{
    struct rr_nsec3param *rr = (struct rr_nsec3param *)rrv;
    char ss[1024];
	char *s = ss;
	int l;
	int i;

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

static struct binary_data nsec3param_wirerdata(struct rr *rrv)
{
    struct rr_nsec3param *rr = (struct rr_nsec3param *)rrv;

	return compose_binary_data("112b", 1,
		rr->hash_algorithm, rr->flags,
		rr->iterations, rr->salt);
}

struct rr_methods nsec3param_methods = { nsec3param_parse, nsec3param_human, nsec3param_wirerdata, NULL, NULL };
