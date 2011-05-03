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

static struct rr* nsec3_parse(char *name, long ttl, int type, char *s)
{
    struct rr_nsec3 *rr = getmem(sizeof(*rr));
	struct rr *ret_rr;
	struct binary_data bitmap;
	int i;
	int opt_out = 0;
	char *str_type = NULL;
	int ltype;

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

	if (!(i == 0 || i == 1))
		return bitch("unsupported flags value");
	if (i == 1)
		opt_out = 1;
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
		rr->salt = extract_hex_binary_data(&s, "salt", EXTRACT_DONT_EAT_WHITESPACE);
		if (rr->salt.length <= 0)
			return NULL;
		if (rr->salt.length > 255)
			return bitch("salt is too long");
	}

	rr->next_hashed_owner = extract_base32hex_binary_data(&s, "next hashed owner");
	if (rr->next_hashed_owner.length != 20) {
		return bitch("next hashed owner does not have the right size");
	}

	bitmap = new_set();
	while (s && *s) {
		str_type = extract_label(&s, "type list", "temporary");
		if (!str_type) return NULL;
		ltype = str2rdtype(str_type);
		add_bit_to_set(&bitmap, ltype);
	}
	if (!s)
		return NULL;
	rr->type_bitmap = compressed_set(&bitmap);

    ret_rr = store_record(type, name, ttl, rr);
	if (ret_rr) {
		G.nsec3_present = 1;
		if (opt_out)
			G.nsec3_opt_out_present = 1;
		if (ret_rr && !nsec3param)
			nsec3param = ret_rr;
	}
	return ret_rr;
}

static char* nsec3_human(struct rr *rrv)
{
    struct rr_nsec3 *rr = (struct rr_nsec3 *)rrv;
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

static struct binary_data nsec3_wirerdata(struct rr *rrv)
{
    struct rr_nsec3 *rr = (struct rr_nsec3 *)rrv;

	return compose_binary_data("112bbd", 1,
		rr->hash_algorithm, rr->flags,
		rr->iterations, rr->salt,
		rr->next_hashed_owner, rr->type_bitmap);
}

struct rr_methods nsec3_methods = { nsec3_parse, nsec3_human, nsec3_wirerdata, NULL, NULL };
