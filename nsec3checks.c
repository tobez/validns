/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
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
#include "base32hex.h"

#include "cbtree.h"

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
uint32_t mask;
struct binary_data *sorted_hashed_names;
void *nsec3_hash;

static int
validate_nsec3_for_name(const char *name, intptr_t *data, void *p)
{
    struct named_rr *named_rr = *((struct named_rr **)data);
    struct binary_data hash;
    struct rr_nsec3 **nsec3_slot;
    struct rr_nsec3 *nsec3;

    if ((named_rr->flags & mask) == NAME_FLAG_KIDS_WITH_RECORDS) {
        //fprintf(stderr, "--- need nsec3, kids with records: %s\n", named_rr->name);
needs_nsec3:
        freeall_temp();
        hash = name2hash(named_rr->name, nsec3param);
        if (hash.length < 0) {
            moan(named_rr->file_name, named_rr->line, "internal: cannot calculate hashed name");
            goto next;
        }
        if (hash.length != 20)
            croak(4, "assertion failed: wrong hashed name size %d", hash.length);
        JHSG(nsec3_slot, nsec3_hash, hash.data, hash.length);
        if (nsec3_slot == PJERR)
            croak(5, "perform_remaining_nsec3checks: JHSG failed");
        if (!nsec3_slot) {
            moan(named_rr->file_name, named_rr->line,
                 "no corresponding NSEC3 found for %s",
                 named_rr->name);
            goto next;
        }
        nsec3 = *nsec3_slot;
        if (!nsec3)
            croak(6, "assertion failed: existing nsec3 from hash is empty");
        nsec3->corresponding_name = named_rr;
        sorted_hashed_names_count++;
        check_typemap(nsec3->type_bitmap, named_rr, &nsec3->rr);
    } else if ((named_rr->flags &
                (NAME_FLAG_NOT_AUTHORITATIVE|NAME_FLAG_SIGNED_DELEGATION)) ==
               NAME_FLAG_SIGNED_DELEGATION)
    {
        //fprintf(stderr, "--- need nsec3, signed delegation: %s\n", named_rr->name);
        goto needs_nsec3;
    } else if (!G.nsec3_opt_out_present && (named_rr->flags &
                                            (NAME_FLAG_APEX_PARENT|NAME_FLAG_NOT_AUTHORITATIVE|NAME_FLAG_DELEGATION|NAME_FLAG_HAS_RECORDS)) ==
               0)
    {
        //fprintf(stderr, "--- need nsec3, empty non-term: %s\n", named_rr->name);
        goto needs_nsec3;
    } else if (!G.nsec3_opt_out_present && (named_rr->flags & (NAME_FLAG_DELEGATION|NAME_FLAG_NOT_AUTHORITATIVE))==NAME_FLAG_DELEGATION)
    {
        //fprintf(stderr, "--- need nsec3, no opt-out: %s\n", named_rr->name);
        goto needs_nsec3;
    } else if (!G.nsec3_opt_out_present && (named_rr->flags & (NAME_FLAG_THIS_WITH_RECORDS|NAME_FLAG_NOT_AUTHORITATIVE)) == NAME_FLAG_THIS_WITH_RECORDS)
    {
        //fprintf(stderr, "--- need nsec3, this with records: %s\n", named_rr->name);
        goto needs_nsec3;
    } else {
        //fprintf(stderr, "--- NO need for nsec3: %s\n", named_rr->name);
    }
next:
    return 1;
}

void perform_remaining_nsec3checks(void)
{
    struct rr_nsec3 *nsec3;

    sorted_hashed_names_count = 0;
    mask = NAME_FLAG_NOT_AUTHORITATIVE|NAME_FLAG_NSEC3_ONLY|NAME_FLAG_KIDS_WITH_RECORDS;
    if (G.nsec3_opt_out_present) {
        mask |= NAME_FLAG_DELEGATION;
    }

    cbtree_allprefixed(&zone_data, "", validate_nsec3_for_name, NULL);

    nsec3 = first_nsec3;
    while (nsec3) {
        if (!nsec3->corresponding_name) {
            moan(nsec3->rr.file_name, nsec3->rr.line,
                 "NSEC3 without a corresponding record (or empty non-terminal)");
        }
        nsec3 = nsec3->next_nsec3;
    }
}

void *remember_nsec3(char *name, struct rr_nsec3 *rr)
{
    char hashed_name[33];
    char binary_hashed_name[20];
    int l;
    struct rr_nsec3 **nsec3_slot;

    l = strlen(name);
    if (l < 33 || name[32] != '.')
        return bitch("NSEC3 record name is not valid");
    if (l == 33 && zone_apex_l != 1)  /* root zone */
        return bitch("NSEC3 record name is not valid");
    if (l > 33 && strcmp(name+33, zone_apex) != 0)
        return bitch("NSEC3 record name is not valid");

    memcpy(hashed_name, name, 32);  hashed_name[32] = 0;
    l = decode_base32hex(binary_hashed_name, hashed_name, 20);
    if (l != 20)
        return bitch("NSEC3 record name is not valid");
    JHSI(nsec3_slot, nsec3_hash, binary_hashed_name, 20);
    if (nsec3_slot == PJERR)
        croak(2, "remember_nsec3: JHSI failed");
    if (*nsec3_slot)
        return bitch("multiple NSEC3 with the same record name");
    *nsec3_slot = rr;
    rr->this_hashed_name.length = 20;
    rr->this_hashed_name.data = getmem(20);
    memcpy(rr->this_hashed_name.data, binary_hashed_name, 20);
    return rr;
}

void *check_typemap(struct binary_data type_bitmap, struct named_rr *named_rr, struct rr *reference_rr)
{
    int type;
    char *base;
    int i, k;
    struct rr_set *set;
    uint32_t nsec_distinct_types = 0;
    uint32_t real_distinct_types;

    base = type_bitmap.data;
    while (base - type_bitmap.data < type_bitmap.length) {
        for (i = 0; i < base[1]; i++) {
            for (k = 0; k <= 7; k++) {
                if (base[2+i] & (0x80 >> k)) {
                    type = ((unsigned char)base[0])*256 + i*8 + k;
                    nsec_distinct_types++;
                    set = find_rr_set_in_named_rr(named_rr, type);
                    if (!set) {
                        return moan(reference_rr->file_name, reference_rr->line,
                                    "%s mentions %s, but no such record found for %s",
                                    rdtype2str(reference_rr->rdtype), rdtype2str(type), named_rr->name);
                    }
                }
            }
        }
        base += base[1]+2;
    }
    real_distinct_types = get_rr_set_count(named_rr);
    if (real_distinct_types > nsec_distinct_types) {
        void *bitmap = NULL;
        struct rr_set **rr_set_slot;
        int rc;
        Word_t rcw;
        Word_t rdtype;
        int skipped = 0;

        base = type_bitmap.data;
        while (base - type_bitmap.data < type_bitmap.length) {
            for (i = 0; i < base[1]; i++) {
                for (k = 0; k <= 7; k++) {
                    if (base[2+i] & (0x80 >> k)) {
                        type = ((unsigned char)base[0])*256 + i*8 + k;
                        J1S(rc, bitmap, type);
                    }
                }
            }
            base += base[1]+2;
        }
        rdtype = 0;
        JLF(rr_set_slot, named_rr->rr_sets, rdtype);
        while (rr_set_slot) {
            J1T(rc, bitmap, (*rr_set_slot)->rdtype);
            if (!rc) {
                if ((named_rr->flags & NAME_FLAG_DELEGATION) &&
                    ((*rr_set_slot)->rdtype == T_A ||
                    (*rr_set_slot)->rdtype == T_AAAA))
                {
                    skipped++;
                } else {
                    moan(reference_rr->file_name, reference_rr->line,
                         "%s exists, but %s does not mention it for %s",
                         rdtype2str((*rr_set_slot)->rdtype),
                         rdtype2str(reference_rr->rdtype),
                         named_rr->name);
                    J1FA(rcw, bitmap);
                    return NULL;
                }
            }
            JLN(rr_set_slot, named_rr->rr_sets, rdtype);
        }
        J1FA(rcw, bitmap);
        if (real_distinct_types - skipped > nsec_distinct_types) {
            return moan(reference_rr->file_name, reference_rr->line,
                        "internal: we know %s typemap is wrong, but don't know any details",
                        rdtype2str(reference_rr->rdtype));
        }
    }
    return reference_rr;
}


void nsec3_consistency_policy_check(void)
{
	if (!first_nsec3) return;
	struct rr_nsec3 *nsec3;
	uint8_t first_hash_algorithm=first_nsec3->hash_algorithm;
	uint8_t first_flags=first_nsec3->flags;
	uint16_t first_iterations=first_nsec3->iterations;
	struct binary_data first_salt;
	first_salt.length=first_nsec3->salt.length;
	if (first_nsec3->salt.data) {
		first_salt.data=malloc(first_nsec3->salt.length);
		if (first_salt.data==NULL) {
			croak(1,"out of memory error");
		}
		memcpy(first_salt.data, first_nsec3->salt.data, first_nsec3->salt.length);
	} else {
		first_salt.data=NULL;
	}
	nsec3 = first_nsec3->next_nsec3;
	while (nsec3) {
		if (nsec3->hash_algorithm != first_hash_algorithm) {
			moan(nsec3->rr.file_name, nsec3->rr.line,
				 "inconsistent NSEC3 hash algorithm");
		}
		if (nsec3->flags != first_flags) {
			moan(nsec3->rr.file_name, nsec3->rr.line,
				 "inconsistent NSEC3 flags");
		}
		if (nsec3->iterations != first_iterations) {
			moan(nsec3->rr.file_name, nsec3->rr.line,
				 "inconsistent NSEC3 iterations");
		}
		if (nsec3->salt.length != first_salt.length ||
				nsec3->salt.data==NULL || first_salt.data==NULL ||
				memcmp(nsec3->salt.data,first_salt.data,first_salt.length)!=0) {
			moan(nsec3->rr.file_name, nsec3->rr.line,
				 "inconsistent NSEC3 salt");
		}
		nsec3 = nsec3->next_nsec3;
	}
	free(first_salt.data);
}
