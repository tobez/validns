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
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr_dnskey *all_dns_keys = NULL;

static struct rr* dnskey_cdnskey_parse(char *name, long ttl, int type, char *s)
{
    struct rr_dnskey *rr = getmem(sizeof(*rr));
    struct binary_data key;
    int flags, proto, algorithm;
    unsigned int ac;
    int i;
    static struct rr *result;

    flags = extract_integer(&s, "flags", NULL);
    if (flags < 0) return NULL;
    if (flags & 0xfe7e)
        return bitch("reserved flags bits are set");
    if (flags & 0x0001 && !(flags & 0x0100))
        return bitch("SEP bit is set but Zone Key bit is unset");
    rr->flags = flags;

    /* TODO validate that `name` is the name of the zone if flags have Zone Key bit set */

    proto = extract_integer(&s, "protocol", NULL);
    if (proto < 0) return NULL;
    if (proto != 3)
        return bitch("bad protocol value");
    rr->protocol = proto;

    algorithm = extract_algorithm(&s, "algorithm");
    if (algorithm == ALG_UNSUPPORTED)   return NULL;
    if (algorithm == ALG_PRIVATEDNS || algorithm == ALG_PRIVATEOID) {
        return bitch("private algorithms are not supported in %s", type == T_CDNSKEY ? "CDNSKEY" : "DNSKEY");
    }
    rr->algorithm = algorithm;

    key = extract_base64_binary_data(&s, "public key");
    if (key.length < 0) return NULL;
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
    rr->key_type = KEY_TYPE_UNUSED;

    if (*s) {
        return bitch("garbage after valid %s data", type == T_CDNSKEY ? "CDNSKEY" : "DNSKEY");
    }
    result = store_record(type, name, ttl, rr);
    if (result && type == T_DNSKEY) {
        rr->next_key = all_dns_keys;
        all_dns_keys = rr;
    }
    return result;
}

static char* dnskey_cdnskey_human(struct rr *rrv)
{
    RRCAST(dnskey);
    char s[1024];

    snprintf(s, 1024, "%hu %d %d XXX ; key id = %hu",
             rr->flags, rr->protocol, rr->algorithm, rr->key_tag);
    return quickstrdup_temp(s);
}

static struct binary_data dnskey_cdnskey_wirerdata(struct rr *rrv)
{
    RRCAST(dnskey);

    return compose_binary_data("211d", 1,
        rr->flags, rr->protocol, rr->algorithm,
        rr->pubkey);
}

static void *dnskey_cdnskey_validate(struct rr *rrv)
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

struct rr_methods dnskey_methods = { dnskey_cdnskey_parse, dnskey_cdnskey_human, dnskey_cdnskey_wirerdata, NULL, dnskey_cdnskey_validate };
struct rr_methods cdnskey_methods = { dnskey_cdnskey_parse, dnskey_cdnskey_human, dnskey_cdnskey_wirerdata, NULL, dnskey_cdnskey_validate };

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
        BIGNUM *n, *e;

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

        e = BN_bin2bn(pk, e_bytes, NULL);
        pk += e_bytes;
        l -= e_bytes;

        n = BN_bin2bn(pk, l, NULL);
        if (!e || !n)
            goto done;

        RSA_set0_key(rsa, n, e, NULL);

        pkey = EVP_PKEY_new();
        if (!pkey)
            goto done;

        if (!EVP_PKEY_set1_RSA(pkey, rsa))
            goto done;

        rr->pkey = pkey;
    } else if (algorithm_type(rr->algorithm) == ALG_ECC_FAMILY) {
        EC_KEY *pubeckey;
        EVP_PKEY *pkey;
        unsigned char *pk;
        int l;
        BIGNUM *bn_x = NULL;
        BIGNUM *bn_y = NULL;

        if (rr->algorithm == ALG_ECDSAP256SHA256) {
            l = SHA256_DIGEST_LENGTH;
            pubeckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        } else if (rr->algorithm == ALG_ECDSAP384SHA384) {
            l = SHA384_DIGEST_LENGTH;
            pubeckey = EC_KEY_new_by_curve_name(NID_secp384r1);
        } else {
            goto done;
        }

        if (!pubeckey)
            goto done;

        if (rr->pubkey.length != 2*l) {
            goto done;
        }

        pk = (unsigned char *)rr->pubkey.data;

        bn_x = BN_bin2bn(pk, l, NULL);
        bn_y = BN_bin2bn(&pk[l], l, NULL);

        if (1 != EC_KEY_set_public_key_affine_coordinates(pubeckey, bn_x, bn_y)) {
            goto done;
        }

        pkey = EVP_PKEY_new();
        if (!pkey)
            goto done;

        if (!EVP_PKEY_assign_EC_KEY(pkey, pubeckey))
            goto done;

        rr->pkey = pkey;
    }
done:
    if (!rr->pkey) {
        moan(rr->rr.file_name, rr->rr.line, "error building pkey");
    }
    return rr->pkey ? 1 : 0;
}

void
dnskey_ksk_policy_check(void)
{
    struct rr_dnskey *rr = all_dns_keys;
    int ksk_found = 0;

    while (rr) {
        if (rr->key_type == KEY_TYPE_KSK)
            ksk_found = 1;
        rr = rr->next_key;
    }
    if (!ksk_found)
        moan(all_dns_keys->rr.file_name, all_dns_keys->rr.line, "No KSK found");
}

