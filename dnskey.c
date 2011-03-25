/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <netinet/in.h>

#include "common.h"
#include "rr.h"

static void* dnskey_parse(char *name, long ttl, int type, char *s)
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

	algorithm = extract_integer(&s, "algorithm");
	if (algorithm < 0)	return NULL;
	if (algorithm != 3 && algorithm != 5 &&
		algorithm != 8 && algorithm != 10)
	{
		return bitch("bad or unsupported algorithm %d", algorithm);
	}
	rr->algorithm = algorithm;

	key = extract_base64_binary_data(&s, "public key");
	if (key.length < 0)	return NULL;
	/* TODO validate key length based on algorithm */
	rr->pubkey_len = key.length;
	rr->pubkey = key.data;

	ac = 0;
	ac += rr->flags;
	ac += rr->protocol << 8;
	ac += rr->algorithm;
	for (i = 0; i < rr->pubkey_len; i++) {
		ac += (i & 1) ? (unsigned char)rr->pubkey[i] : ((unsigned char)rr->pubkey[i]) << 8;
	}
	ac += (ac >> 16) & 0xFFFF;
	rr->key_tag = ac & 0xFFFF;

	if (*s) {
		return bitch("garbage after valid DNSKEY data");
	}
	return store_record(type, name, ttl, rr);
}

static char* dnskey_human(void *rrv)
{
    struct rr_dnskey *rr = rrv;
    char s[1024];

    snprintf(s, 1024, "%hu %d %d XXX ; key id = %hu",
			 rr->flags, rr->protocol, rr->algorithm, rr->key_tag);
    return quickstrdup_temp(s);
}

static void* dnskey_wirerdata(void *rrv)
{
    struct rr_dnskey *rr = rrv;

    return NULL;
}

struct rr_methods dnskey_methods = { dnskey_parse, dnskey_human, dnskey_wirerdata };
