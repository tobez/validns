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
	void *x = name2hash;
	x = name2hash;

	sorted_hashed_names_count = 0;
	if (G.nsec3_opt_out_present) {
		uint32_t rrs;

/* Yuck!  Delegated ns.xyz -> A records are also not covered by NSEC3! */
		sorted_name[0] = 0;
		JSLF(named_rr_p, zone_data, sorted_name);
		while (named_rr_p) {
			if ((*named_rr_p)->rr_sets) {
				rrs = get_rr_set_count(*named_rr_p);
				if (rrs == 1) {
					/* could be opt-out NS delegation, or unsigned NSEC3 (the possibility of which we ignore) */
					if (!find_rr_set_in_named_rr(*named_rr_p, T_NS)) {
//fprintf(stderr, "1: %s\n", (*named_rr_p)->name);
						sorted_hashed_names_count++;
					}
				} else if (rrs == 2) {
					/* could be signed NSEC3 */
					if (!find_rr_set_in_named_rr(*named_rr_p, T_NSEC3)) {
//fprintf(stderr, "2: %s\n", (*named_rr_p)->name);
						sorted_hashed_names_count++;
					}
				} else {
//fprintf(stderr, "%d: %s\n", rrs, (*named_rr_p)->name);
					sorted_hashed_names_count++;
				}
			} else {
				/* must be empty non-terminal */
				sorted_hashed_names_count++;
			}
			JSLN(named_rr_p, zone_data, sorted_name);
		}
//fprintf(stderr, "found sorted_hashed_names_count: %d\n", sorted_hashed_names_count);
	} else {
		sorted_hashed_names_count = G.stats.names_count;
	}
}
