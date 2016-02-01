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

struct rr *nsec3param = NULL;

static struct rr* nsec3param_parse(char *name, long ttl, int type, char *s)
{
    struct rr_nsec3param *rr = getmem(sizeof(*rr));
	struct rr *ret_rr;
	int i;

	i = extract_integer(&s, "hash algorithm", NULL);
	if (i < 0)
		return NULL;
	if (i > 255)
		return bitch("bad hash algorithm value");
	if (i != 1)
		return bitch("unrecognized or unsupported hash algorithm");
	rr->hash_algorithm = i;

	i = extract_integer(&s, "flags", NULL);
	if (i < 0)
		return NULL;
	if (i > 255)
		return bitch("bad flags value");
	if (i != 0)
		return bitch("flags is supposed to be 0 for NSEC3PARAM");
	rr->flags = i;

	i = extract_integer(&s, "iterations", NULL);
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
		rr->salt = extract_hex_binary_data(&s, "salt", EXTRACT_DONT_EAT_WHITESPACE);
		if (rr->salt.length <= 0)
			return NULL;
		if (rr->salt.length > 255)
			return bitch("salt is too long");
	}
	if (*s) {
		return bitch("garbage after valid NSEC3PARAM data");
	}

	G.dnssec_active = 1;
    ret_rr = store_record(type, name, ttl, rr);
	if (ret_rr && !nsec3param && (ret_rr->rr_set->named_rr->flags & NAME_FLAG_APEX))
		nsec3param = ret_rr;
	if (G.opt.policy_checks[POLICY_NSEC3PARAM_NOT_APEX] &&
		(ret_rr->rr_set->named_rr->flags & NAME_FLAG_APEX) == 0)
	{
		return bitch("NSEC3PARAM found not at zone apex");
	}
	return ret_rr;
}

static char* nsec3param_human(struct rr *rrv)
{
	RRCAST(nsec3param);
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
	RRCAST(nsec3param);

	return compose_binary_data("112b", 1,
		rr->hash_algorithm, rr->flags,
		rr->iterations, rr->salt);
}

struct rr_methods nsec3param_methods = { nsec3param_parse, nsec3param_human, nsec3param_wirerdata, NULL, NULL };
