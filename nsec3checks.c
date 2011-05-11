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
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <Judy.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct binary_data name2hash(char *name, struct rr *param)
{
    struct rr_nsec3param *p = (struct rr_nsec3param *)param;
	EVP_MD_CTX ctx;
	unsigned char md0[EVP_MAX_MD_SIZE];
	unsigned char md1[EVP_MAX_MD_SIZE];
	unsigned char *md[2];
	int mdi = 0;
	struct binary_data r = bad_binary_data();
	struct binary_data wire_name = name2wire_name(name);
	int i;
	int digest_size;

	md[0] = md0;
	md[1] = md1;
	if (wire_name.length < 0)
		return r;

	/* XXX Maybe use Init_ex and Final_ex for speed? */

	EVP_MD_CTX_init(&ctx);
	if (EVP_DigestInit(&ctx, EVP_sha1()) != 1)
		return r;
	digest_size = EVP_MD_CTX_size(&ctx);
	EVP_DigestUpdate(&ctx, wire_name.data, wire_name.length);
	EVP_DigestUpdate(&ctx, p->salt.data, p->salt.length);
	EVP_DigestFinal(&ctx, md[mdi], NULL);

	for (i = 0; i < p->iterations; i++) {
		if (EVP_DigestInit(&ctx, EVP_sha1()) != 1)
			return r;
		EVP_DigestUpdate(&ctx, md[mdi], digest_size);
		mdi = (mdi + 1) % 2;
		EVP_DigestUpdate(&ctx, p->salt.data, p->salt.length);
		EVP_DigestFinal(&ctx, md[mdi], NULL);
	}

	r.length = digest_size;
	r.data = getmem(digest_size);
	memcpy(r.data, md[mdi], digest_size);
	return r;
}

int sorted_hashed_names_count;
struct binary_data *sorted_hashed_names;

extern void calculate_hashed_names(void)
{
	unsigned char sorted_name[512];
	struct named_rr **named_rr_p;
	struct named_rr *named_rr;
	void *x = name2hash;
	x = name2hash;
	uint32_t mask;

	sorted_hashed_names_count = 0;
	mask = NAME_FLAG_NOT_AUTHORITATIVE|NAME_FLAG_NSEC3_ONLY;
	if (G.nsec3_opt_out_present) {
		mask |= NAME_FLAG_DELEGATION;
	}

	sorted_name[0] = 0;
	JSLF(named_rr_p, zone_data, sorted_name);
	while (named_rr_p) {
		named_rr = *named_rr_p;
		if ((named_rr->flags & mask) == 0) {
/* debug
struct binary_data hash;
int i;
Word_t rdtype;
struct rr_set **rr_set_p;

hash = name2hash(named_rr->name, nsec3param);
for (i = 0; i < hash.length; i++) {
	fprintf(stderr, "%02x", (unsigned char)hash.data[i]);
}

rdtype = 0;
JLF(rr_set_p, named_rr->rr_sets, rdtype);
while (rr_set_p) {
	fprintf(stderr, " %s", rdtype2str(rdtype));
	JLN(rr_set_p, named_rr->rr_sets, rdtype);
}

fprintf(stderr, " %s\n", named_rr->name);
*/
			sorted_hashed_names_count++;
		}
		JSLN(named_rr_p, zone_data, sorted_name);
	}
/* fprintf(stderr, "found sorted_hashed_names_count: %d\n", sorted_hashed_names_count); */
}
