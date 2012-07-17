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
#include <string.h>
#include <ctype.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

/* See http://tools.ietf.org/html/rfc4398 for CERT description.
 * See http://www.iana.org/assignments/cert-rr-types/cert-rr-types.xml
 * for certificate types.  The version implemented here
 * has "Last Updated" equal to "2006-09-27" */

static int extract_certificate_type(char **s, char *what)
{
	int type;
	char *str_type;

	if (isdigit(**s)) {
		type = extract_integer(s, what);
		if (type >= 1 && type <= 8)
			return type;
		if (type == 253 || type == 254)
			return type;
		if (type >= 65280 && type <= 65534)
			return type;
		if (type < 0 || type > 65535) {
			bitch("bad certificate type %d", type);
			return -1;
		}
		if (type == 0 || type == 255 || type == 65535) {
			bitch("certificate type %d is reserved by IANA", type);
			return -1;
		}
		bitch("certificate type %d is unassigned", type);
		return -1;
	} else {
		str_type = extract_label(s, what, "temporary");
		if (!str_type) return -1;
		if (strcmp(str_type, "pkix") == 0)
			return 1;
		if (strcmp(str_type, "spki") == 0)
			return 2;
		if (strcmp(str_type, "pgp") == 0)
			return 3;
		if (strcmp(str_type, "ipkix") == 0)
			return 4;
		if (strcmp(str_type, "ispki") == 0)
			return 5;
		if (strcmp(str_type, "ipgp") == 0)
			return 6;
		if (strcmp(str_type, "acpkix") == 0)
			return 7;
		if (strcmp(str_type, "iacpkix") == 0)
			return 8;
		if (strcmp(str_type, "uri") == 0)
			return 253;
		if (strcmp(str_type, "oid") == 0)
			return 254;
		bitch("bad certificate type %s", str_type);
		return -1;
	}
}

static struct rr* cert_parse(char *name, long ttl, int type, char *s)
{
	struct rr_cert *rr = getmem(sizeof(*rr));
	int cert_type, key_tag, alg;

	cert_type = extract_certificate_type(&s, "certificate type");
	if (cert_type < 0)	return NULL;
	rr->type = cert_type;

	key_tag = extract_integer(&s, "key tag");
	if (key_tag < 0)	return NULL;
	if (key_tag > 65535)
		return bitch("bad key tag");
	rr->key_tag = key_tag;

	if (isdigit(*s)) {
		alg = extract_integer(&s, "algorithm");
		if (alg < 0)	return NULL;
		if (alg > 255)	return bitch("bad algorithm");
		if (alg != 0) {  /* 0 is just fine */
			if (algorithm_type(alg) == ALG_UNSUPPORTED)
				return bitch("bad algorithm %d", alg);
		}
	} else {
		alg = extract_algorithm(&s, "algorithm");
		if (alg == ALG_UNSUPPORTED)	return NULL;
	}
	rr->algorithm = alg;

	if (alg == 0 && key_tag != 0) {
		/* we might want to bitch here, but RFC says "SHOULD", so we don't */
	}

	rr->certificate = extract_base64_binary_data(&s, "certificate");
	if (rr->certificate.length < 0)	return NULL;
	/* TODO validate cert length based on algorithm */

	if (*s) {
		return bitch("garbage after valid CERT data");
	}
	return store_record(type, name, ttl, rr);
}

static char* cert_human(struct rr *rrv)
{
	RRCAST(cert);
    char s[1024];

    snprintf(s, 1024, "%d %d %d ...",
		rr->type, rr->key_tag, rr->algorithm);
    return quickstrdup_temp(s);
}

static struct binary_data cert_wirerdata(struct rr *rrv)
{
	RRCAST(cert);

	return compose_binary_data("221d", 1,
		rr->type, rr->key_tag, rr->algorithm,
		rr->certificate);
}

struct rr_methods cert_methods = { cert_parse, cert_human, cert_wirerdata, NULL, NULL };
