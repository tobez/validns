/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

/* See http://www.rfc-editor.org/internet-drafts/draft-ietf-dane-protocol-23.txt
 * for TLSA description.
 */

static struct rr* tlsa_parse(char *name, long ttl, int type, char *s)
{
	struct rr_tlsa *rr = getmem(sizeof(*rr));
	int cert_usage, selector, matching_type;

	cert_usage = extract_integer(&s, "certificate usage field");
	if (cert_usage < 0)	return NULL;
	if (cert_usage > 3)
		return bitch("bad certificate usage field");
	rr->cert_usage = cert_usage;

	selector = extract_integer(&s, "selector field");
	if (selector < 0)	return NULL;
	if (selector > 1)
		return bitch("bad selector field");
	rr->selector = selector;

	matching_type = extract_integer(&s, "matching type field");
	if (matching_type < 0)	return NULL;
	if (matching_type > 2)
		return bitch("bad matching type field");
	rr->matching_type = matching_type;

	rr->association_data = extract_hex_binary_data(&s, "certificate association data", EXTRACT_EAT_WHITESPACE);
	if (rr->association_data.length < 0)	return NULL;
	switch (rr->matching_type) {
	case 1:
		if (rr->association_data.length != SHA256_BYTES)
			return bitch("bad SHA-256 hash length");
		break;
	case 2:
		if (rr->association_data.length != SHA512_BYTES)
			return bitch("bad SHA-512 hash length");
		break;
	}

	if (*s) {
		return bitch("garbage after valid TLSA data");
	}
	return store_record(type, name, ttl, rr);
}

static char* tlsa_human(struct rr *rrv)
{
	RRCAST(tlsa);
    char s[1024];

    snprintf(s, 1024, "%d %d %d ...",
		rr->cert_usage, rr->selector, rr->matching_type);
    return quickstrdup_temp(s);
}

static struct binary_data tlsa_wirerdata(struct rr *rrv)
{
	RRCAST(tlsa);

	return compose_binary_data("111d", 1,
		rr->cert_usage, rr->selector, rr->matching_type,
		rr->association_data);
}

static void* tlsa_validate_set(struct rr_set *rr_set)
{
	struct rr *rr;
	struct named_rr *named_rr;
	char *s;
	int port = 0;
	int len;

	if (G.opt.policy_checks[POLICY_TLSA_HOST]) {
		rr = rr_set->tail;
		named_rr = rr_set->named_rr;

		/* _25._tcp.mail.example.com. */
		s = named_rr->name;
		if (*s != '_') {
not_a_prefixed_domain_name:
			return moan(rr->file_name, rr->line, "not a proper prefixed DNS domain name");
		}
		s++;
		while (isdigit(*s)) {
			port = port * 10  + *s - '0';
			s++;
		}
		if (port <= 0 || port > 65535)	goto not_a_prefixed_domain_name;
		if (*s++ != '.')	goto not_a_prefixed_domain_name;
		len = strlen(s);
		if (len < 6)	goto not_a_prefixed_domain_name;
		if (memcmp(s, "_tcp.", 5) != 0 &&
			memcmp(s, "_udp.", 5) != 0 &&
			memcmp(s, "_sctp.", 6) != 0)	goto not_a_prefixed_domain_name;
	}
	return NULL;
}

struct rr_methods tlsa_methods = { tlsa_parse, tlsa_human, tlsa_wirerdata, tlsa_validate_set, NULL };
