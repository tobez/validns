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

static struct rr* rrsig_parse(char *name, long ttl, int type, char *s)
{
	struct rr_rrsig *rr = getmem(sizeof(*rr));
	int type_covered, key_tag;
	char *str_type_covered;
	struct binary_data sig;

	str_type_covered = extract_label(&s, "type covered", "temporary");
	if (!str_type_covered) return NULL;
	type_covered = str2rdtype(str_type_covered);
	if (type_covered <= 0 || type_covered > T_MAX) return NULL;
	rr->type_covered = type_covered;

	rr->algorithm = extract_integer(&s, "algorithm");
	if (rr->algorithm < 0)	return NULL;
	if (rr->algorithm != 3 && rr->algorithm != 5 &&
		rr->algorithm != 8 && rr->algorithm != 10)
	{
		return bitch("bad or unsupported algorithm %d", rr->algorithm);
	}

	rr->labels = extract_integer(&s, "labels");
	if (rr->labels < 0)	return NULL;
	/* TODO validate labels, see http://tools.ietf.org/html/rfc4034#section-3.1.3 */

	rr->orig_ttl = extract_timevalue(&s, "original TTL");
	if (rr->orig_ttl < 0) return NULL;

	rr->sig_expiration = extract_timestamp(&s, "signature expiration");
	if (rr->sig_expiration < 0) return NULL;

	rr->sig_inception = extract_timestamp(&s, "signature inception");
	if (rr->sig_inception < 0) return NULL;

	key_tag = extract_integer(&s, "key tag");
	if (key_tag < 0)	return NULL;
	rr->key_tag = key_tag;

	rr->signer = extract_name(&s, "signer name");
	if (!rr->signer) return NULL;
	/* TODO validate signer name, http://tools.ietf.org/html/rfc4034#section-3.1.7 */

	sig = extract_base64_binary_data(&s, "signature");
	if (sig.length < 0)	return NULL;
	/* TODO validate signature length based on algorithm */
	rr->sig_len = sig.length;
	rr->signature = sig.data;

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

static struct binary_data rrsig_wirerdata(struct rr *rrv)
{
    return bad_binary_data();
}

static void *rrsig_validate(struct rr *rrv)
{
	struct rr_rrsig *rr = (struct rr_rrsig *)rrv;
	struct named_rr *named_rr;
	struct rr_set *signed_set;

	named_rr = rr->rr.rr_set->named_rr;
	signed_set = find_rr_set_in_named_rr(named_rr, rr->type_covered);
	if (!signed_set) {
		return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG exists for non-existing type %s", named_rr->name, rdtype2str(rr->type_covered));
	}
	if (signed_set->tail->ttl != rr->orig_ttl) {
		return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG's original TTL differs from corresponding record's", named_rr->name);
	}
	return rr;
}

struct rr_methods rrsig_methods = { rrsig_parse, rrsig_human, rrsig_wirerdata, NULL, rrsig_validate };
