#include "common.h"
#include "rr.h"

static void* rrsig_parse(char *name, long ttl, char *s)
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
	return store_record(T_RRSIG, name, ttl, rr);
}

static char* rrsig_human(void *rrv)
{
    struct rr_rrsig *rr = rrv;
    char s[1024];

    //snprintf(s, 1024, "SOA %s %s %d %d %d %d %d",
	 //    rr->mname, rr->rname, rr->serial,
	  //   rr->refresh, rr->retry, rr->expire, rr->minimum);
    //return quickstrdup_temp(s);
	return NULL;
}

static void* rrsig_wirerdata(void *rrv)
{
    struct rr_rrsig *rr = rrv;

    return NULL;
}

struct rr_methods rrsig_methods = { rrsig_parse, rrsig_human, rrsig_wirerdata };
