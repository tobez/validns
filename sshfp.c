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

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr* sshfp_parse(char *name, long ttl, int type, char *s)
{
    struct rr_sshfp *rr = getmem(sizeof(*rr));
    int algorithm, fp_type;

    algorithm = extract_integer(&s, "algorithm", NULL);
    if (algorithm < 0)  return NULL;
    if (algorithm != 1 && algorithm != 2 && algorithm != 3 && algorithm != 4 && algorithm != 5 )
        return bitch("unsupported algorithm");
    rr->algorithm = algorithm;

    fp_type = extract_integer(&s, "fp type", NULL);
    if (fp_type < 0)    return NULL;
    if (fp_type != 1 && fp_type != 2)
        return bitch("unsupported fp_type");
    rr->fp_type = fp_type;

    rr->fingerprint = extract_hex_binary_data(&s, "fingerprint", EXTRACT_EAT_WHITESPACE);
    if (rr->fingerprint.length < 0) return NULL;
    
    if (rr->fp_type == 1 && rr->fingerprint.length != SHA1_BYTES) {
        return bitch("wrong SHA-1 fingerprint length: %d bytes found, %d bytes expected",
                     rr->fingerprint.length, SHA1_BYTES);
    }
    if (rr->fp_type == 2 && rr->fingerprint.length != SHA256_BYTES) {
        return bitch("wrong SHA-256 fingerprint length: %d bytes found, %d bytes expected",
                     rr->fingerprint.length, SHA256_BYTES);
    }

    if (*s) {
        return bitch("garbage after valid SSHFP data");
    }
    return store_record(type, name, ttl, rr);
}

static char* sshfp_human(struct rr *rrv)
{
    RRCAST(sshfp);
    char ss[4096];
    char *s = ss;
    int l;
    int i;

    l = snprintf(s, 4096, "%u %u ", rr->algorithm, rr->fp_type);
    s += l;
    for (i = 0; i < rr->fingerprint.length; i++) {
        l = snprintf(s, 4096-(s-ss), "%02X", (unsigned char)rr->fingerprint.data[i]);
        s += l;
    }
    return quickstrdup_temp(ss);
}

static struct binary_data sshfp_wirerdata(struct rr *rrv)
{
    RRCAST(sshfp);

    return compose_binary_data("11d", 1,
        rr->algorithm, rr->fp_type,
        rr->fingerprint);
}

struct rr_methods sshfp_methods = { sshfp_parse, sshfp_human, sshfp_wirerdata, NULL, NULL };
