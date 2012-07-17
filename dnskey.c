/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, 2012 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr* dnskey_parse(char *name, long ttl, int type, char *s)
{
	struct rr_dnskey *rr = getmem(sizeof(*rr));
	struct binary_data key;
	int flags, proto, algorithm;
	unsigned int ac;
	int i;

	flags = extract_integer(&s, "flags");
	if (flags < 0) return NULL;
	if (flags & 0xfefe)
		return bitch("reserved flags bits are set");
	if (flags & 0x0001 && !(flags & 0x0100))
		return bitch("SEP bit is set but Zone Key bit is unset");
	rr->flags = flags;

	/* TODO validate that `name` is the name of the zone if flags have Zone Key bit set */

	proto = extract_integer(&s, "protocol");
	if (proto < 0) return NULL;
	if (proto != 3)
		return bitch("bad protocol value");
	rr->protocol = proto;

	algorithm = extract_algorithm(&s, "algorithm");
	if (algorithm == ALG_UNSUPPORTED)	return NULL;
	if (algorithm == ALG_PRIVATEDNS || algorithm == ALG_PRIVATEOID) {
		return bitch("private algorithms are not supported in DNSKEY");
	}
	rr->algorithm = algorithm;

	key = extract_base64_binary_data(&s, "public key");
	if (key.length < 0)	return NULL;
	/* TODO validate key length based on algorithm */
	rr->pubkey = key;

	ac = 0;
	ac += rr->flags;
	ac += rr->protocol << 8;
	ac += rr->algorithm;
	for (i = 0; i < rr->pubkey.length; i++) {
		ac += (i & 1) ? (unsigned char)rr->pubkey.data[i] : ((unsigned char)rr->pubkey.data[i]) << 8;
	}
	ac += (ac >> 16) & 0xFFFF;
	rr->key_tag = ac & 0xFFFF;

	rr->pkey_built = 0;
	rr->pkey = NULL;

	if (*s) {
		return bitch("garbage after valid DNSKEY data");
	}
	return store_record(type, name, ttl, rr);
}

static char* dnskey_human(struct rr *rrv)
{
	RRCAST(dnskey);
    char s[1024];

    snprintf(s, 1024, "%hu %d %d XXX ; key id = %hu",
			 rr->flags, rr->protocol, rr->algorithm, rr->key_tag);
    return quickstrdup_temp(s);
}

static struct binary_data dnskey_wirerdata(struct rr *rrv)
{
	RRCAST(dnskey);

	return compose_binary_data("211d", 1,
		rr->flags, rr->protocol, rr->algorithm,
		rr->pubkey);
}

static void *dnskey_validate(struct rr *rrv)
{
	RRCAST(dnskey);

	if (G.opt.policy_checks[POLICY_DNSKEY]) {
		if (algorithm_type(rr->algorithm) == ALG_RSA_FAMILY) {
			unsigned int e_bytes;
			unsigned char *pk;
			int l;

			pk = (unsigned char *)rr->pubkey.data;
			l = rr->pubkey.length;

			e_bytes = *pk++;
			l--;
			if (e_bytes == 0) {
				if (l < 2)
					return moan(rr->rr.file_name, rr->rr.line, "public key is too short");
				e_bytes = (*pk++)  << 8;
				e_bytes += *pk++;
				l -= 2;
			}
			if (l < e_bytes)
				return moan(rr->rr.file_name, rr->rr.line, "public key is too short");

			if (*pk == 0)
				return moan(rr->rr.file_name, rr->rr.line, "leading zero octets in public key exponent");
			pk += e_bytes;
			l -= e_bytes;
			if (l > 0 && *pk == 0)
				return moan(rr->rr.file_name, rr->rr.line, "leading zero octets in key modulus");
		}
	}
	return NULL;
}

struct rr_methods dnskey_methods = { dnskey_parse, dnskey_human, dnskey_wirerdata, NULL, dnskey_validate };

int dnskey_build_pkey(struct rr_dnskey *rr)
{
	if (rr->pkey_built)
		return rr->pkey ? 1 : 0;

	rr->pkey_built = 1;

	if (algorithm_type(rr->algorithm) == ALG_RSA_FAMILY) {
		RSA *rsa;
		EVP_PKEY *pkey;
		unsigned int e_bytes;
		unsigned char *pk;
		int l;

		rsa = RSA_new();
		if (!rsa)
			goto done;

		pk = (unsigned char *)rr->pubkey.data;
		l = rr->pubkey.length;

		e_bytes = *pk++;
		l--;
		if (e_bytes == 0) {
			if (l < 2) /* public key is too short */
				goto done;
			e_bytes = (*pk++)  << 8;
			e_bytes += *pk++;
			l -= 2;
		}
		if (l < e_bytes) /* public key is too short */
			goto done;

		rsa->e = BN_bin2bn(pk, e_bytes, NULL);
		pk += e_bytes;
		l -= e_bytes;

		rsa->n = BN_bin2bn(pk, l, NULL);

		pkey = EVP_PKEY_new();
		if (!pkey)
			goto done;

		if (!EVP_PKEY_set1_RSA(pkey, rsa))
			goto done;

		rr->pkey = pkey;
	}
done:
	if (!rr->pkey) {
		moan(rr->rr.file_name, rr->rr.line, "error building pkey");
	}
	return rr->pkey ? 1 : 0;
}

