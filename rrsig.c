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
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

/* FreeBSD-only?   Debug, anyway.  */
// #include <libutil.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr* rrsig_parse(char *name, long ttl, int type, char *s)
{
	struct rr_rrsig *rr = getmem(sizeof(*rr));
	int type_covered, key_tag;
	char *str_type_covered;
	struct binary_data sig;
	long long ts;

	str_type_covered = extract_label(&s, "type covered", "temporary");
	if (!str_type_covered) return NULL;
	type_covered = str2rdtype(str_type_covered);
	if (type_covered <= 0 || type_covered > 65535) return NULL;
	rr->type_covered = type_covered;

	rr->algorithm = extract_algorithm(&s, "algorithm");
	if (rr->algorithm == ALG_UNSUPPORTED)	return NULL;

	rr->labels = extract_integer(&s, "labels");
	if (rr->labels < 0)	return NULL;
	/* TODO validate labels, see http://tools.ietf.org/html/rfc4034#section-3.1.3 */

	rr->orig_ttl = extract_timevalue(&s, "original TTL");
	if (rr->orig_ttl < 0) return NULL;

	ts = extract_timestamp(&s, "signature expiration");
	if (ts < 0) return NULL;
	rr->sig_expiration = ts;

	ts = extract_timestamp(&s, "signature inception");
	if (ts < 0) return NULL;
	rr->sig_inception = ts;

	key_tag = extract_integer(&s, "key tag");
	if (key_tag < 0)	return NULL;
	rr->key_tag = key_tag;

	rr->signer = extract_name(&s, "signer name");
	if (!rr->signer) return NULL;
	/* TODO validate signer name, http://tools.ietf.org/html/rfc4034#section-3.1.7 */

	sig = extract_base64_binary_data(&s, "signature");
	if (sig.length < 0)	return NULL;
	/* TODO validate signature length based on algorithm */
	rr->signature = sig;

	if (*s) {
		return bitch("garbage after valid RRSIG data");
	}
	return store_record(type, name, ttl, rr);
}

static char* rrsig_human(struct rr *rrv)
{
    // struct rr_rrsig *rr = (struct rr_rrsig *)rrv;
    // char s[1024];

    //snprintf(s, 1024, "SOA %s %s %d %d %d %d %d",
	 //    rr->mname, rr->rname, rr->serial,
	  //   rr->refresh, rr->retry, rr->expire, rr->minimum);
    //return quickstrdup_temp(s);
	return NULL;
}

static struct binary_data rrsig_wirerdata_ex(struct rr *rrv, int with_signature)
{
    struct rr_rrsig *rr = (struct rr_rrsig *)rrv;
	struct binary_data bd;

	bd = compose_binary_data("2114442d", 1,
		rr->type_covered, rr->algorithm, rr->labels,
		rr->orig_ttl, rr->sig_expiration, rr->sig_inception,
		rr->key_tag, name2wire_name(rr->signer));
	if (with_signature) {
		return compose_binary_data("dd", 1, bd, rr->signature);
	}
	return bd;
}

static struct binary_data rrsig_wirerdata(struct rr *rrv)
{
	return rrsig_wirerdata_ex(rrv, 1);
}

struct rr_with_wired
{
	struct rr *rr;
	struct binary_data wired;
};

static int compare_rr_with_wired(const void *va, const void *vb)
{
	const struct rr_with_wired *a = va;
	const struct rr_with_wired *b = vb;
	int r;

	if (a->wired.length == b->wired.length) {
		return memcmp(a->wired.data, b->wired.data, a->wired.length);
	} else if (a->wired.length < b->wired.length) {
		r = memcmp(a->wired.data, b->wired.data, a->wired.length);
		if (r != 0) return r;
		return -1;
	} else {
		r = memcmp(a->wired.data, b->wired.data, b->wired.length);
		if (r != 0) return r;
		return 1;
	}
}

static int verify_signature(struct rr_rrsig *rr, struct rr_dnskey *key, struct rr_set *signed_set)
{
	EVP_MD_CTX ctx;
	uint16_t b2;
	uint32_t b4;
	struct binary_data chunk;
	struct rr_with_wired *set;
	struct rr *signed_rr;
	int i;
	rr_wire_func get_wired;

	get_wired = signed_set->rdtype > T_MAX ? any_wirerdata : rr_methods[signed_set->rdtype].rr_wire;
	if (!get_wired)
		return 0;

	EVP_MD_CTX_init(&ctx);
	switch (rr->algorithm) {
	case ALG_DSA:
	case ALG_RSASHA1:
	case ALG_DSA_NSEC3_SHA1:
	case ALG_RSASHA1_NSEC3_SHA1:
		if (EVP_VerifyInit(&ctx, EVP_sha1()) != 1)
			return 0;
		break;
	case ALG_RSASHA256:
		if (EVP_VerifyInit(&ctx, EVP_sha256()) != 1)
			return 0;
		break;
	case ALG_RSASHA512:
		if (EVP_VerifyInit(&ctx, EVP_sha512()) != 1)
			return 0;
		break;
	default:
		return 0;
	}

	chunk = rrsig_wirerdata_ex(&rr->rr, 0);
	if (chunk.length < 0)
		return 0;
	EVP_VerifyUpdate(&ctx, chunk.data, chunk.length);

	set = getmem_temp(sizeof(*set) * signed_set->count);

	signed_rr = signed_set->tail;
	i = 0;
	while (signed_rr) {
		set[i].rr = signed_rr;
		set[i].wired = get_wired(signed_rr);
		if (set[i].wired.length < 0)
			return 0;
		i++;
		signed_rr = signed_rr->next;
	}
	qsort(set, signed_set->count, sizeof(*set), compare_rr_with_wired);

	for (i = 0; i < signed_set->count; i++) {
		chunk = name2wire_name(signed_set->named_rr->name);
		if (chunk.length < 0)
			return 0;
		EVP_VerifyUpdate(&ctx, chunk.data, chunk.length);
		b2 = htons(set[i].rr->rdtype);    EVP_VerifyUpdate(&ctx, &b2, 2);
		b2 = htons(1);  /* class IN */   EVP_VerifyUpdate(&ctx, &b2, 2);
		b4 = htonl(set[i].rr->ttl);       EVP_VerifyUpdate(&ctx, &b4, 4);
		b2 = htons(set[i].wired.length); EVP_VerifyUpdate(&ctx, &b2, 2);
		EVP_VerifyUpdate(&ctx, set[i].wired.data, set[i].wired.length);
	}

	G.stats.signatures_verified++;
	if (EVP_VerifyFinal(&ctx, (unsigned char *)rr->signature.data, rr->signature.length, key->pkey) == 1) {
		/* fprintf(stderr, "EXCELLENT(%s %s, alg %d)\n", signed_set->named_rr->name, rdtype2str(signed_set->rdtype), rr->algorithm); */
		return 1;
	}
	return 0;
}

static void *rrsig_validate(struct rr *rrv)
{
	struct rr_rrsig *rr = (struct rr_rrsig *)rrv;
	struct named_rr *named_rr;
	struct rr_set *signed_set;
	struct rr_dnskey *key = NULL;
	struct rr_set *dnskey_rr_set;
	int found_key;

	named_rr = rr->rr.rr_set->named_rr;
	if (G.opt.current_time < rr->sig_inception) {
		return moan(rr->rr.file_name, rr->rr.line, "%s signature is too new", named_rr->name);
	}
	if (G.opt.current_time > rr->sig_expiration) {
		return moan(rr->rr.file_name, rr->rr.line, "%s signature is too old", named_rr->name);
	}
	signed_set = find_rr_set_in_named_rr(named_rr, rr->type_covered);
	if (!signed_set) {
		return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG exists for non-existing type %s", named_rr->name, rdtype2str(rr->type_covered));
	}
	if (signed_set->tail->ttl != rr->orig_ttl) {
		return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG's original TTL differs from corresponding record's", named_rr->name);
	}
	dnskey_rr_set = find_rr_set(T_DNSKEY, rr->signer);
	if (!dnskey_rr_set) {
		return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG(%s): cannot find a signer key (%s)", named_rr->name, rdtype2str(rr->type_covered), rr->signer);
	}
	key = (struct rr_dnskey *)dnskey_rr_set->tail;
	while (key) {
		if (key->algorithm == rr->algorithm && key->key_tag == rr->key_tag) {
			found_key = 1;
			if (dnskey_build_pkey(key) && verify_signature(rr, key, signed_set))
				break;
		}
		key = (struct rr_dnskey *)key->rr.next;
	}
	if (!key) {
		if (found_key) {
			return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG(%s): cannot verify the signature", named_rr->name, rdtype2str(rr->type_covered), rr->signer);
		} else {
			return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG(%s): cannot find the right signer key (%s)", named_rr->name, rdtype2str(rr->type_covered), rr->signer);
		}
	}
	return rr;
}

struct rr_methods rrsig_methods = { rrsig_parse, rrsig_human, rrsig_wirerdata, NULL, rrsig_validate };
