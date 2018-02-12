/*
 * Part of DNS zone file validator `validns`.
            604800  NSEC    example.com. NS DS RRSIG NSEC
            604800  RRSIG   NSEC 10 3 604800 20130321184221 (
                    20130219184221 35615 example.com.
                    WWg7EiYoY8Hp593I2i5Mkl2ezg7YuAnq0y75
                    oymTCuEfGwh4OxbMT/mWNqAFL5Y8f0YoQOOY
                    wZP0m/sGK/EJN7ulNsfQyULY4WsyHIGlKMwT
                    KdyDXJLrmrzlmRnGv7pFb0bo53n3osE0uFfH
                    yMQYOkQRYfqa4yWXF9Nl48dy67frtVih0foy
                    9Mm76mmJSDUd/jGsYQmaoFGVU/a64rWapVQ9
                    O/mXPqr6Pw2ZCHecsF4ElMEp41YqG1DfR5QR
                    khTjvTlg4aTKvgX1YuvDhjUygSHit47xn2NC
                    2WwEZF+vYXT9DIUCMcKdVeb4bjWwUXbWNFqz
                    Ca3jb/mpOpUDFnrRPw== )
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr* nsec_parse(char *name, long ttl, int type, char *s)
{
    struct rr_nsec *rr = getmem(sizeof(*rr));
    struct binary_data bitmap;
    char *str_type = NULL;
    int ltype;

    rr->next_domain = extract_name(&s, "next domain", KEEP_CAPITALIZATION);
    /* TODO: validate next_domain, http://tools.ietf.org/html/rfc4034#section-4.1.1 */

    bitmap = new_set();
    while (s && *s) {
        str_type = extract_label(&s, "type list", "temporary");
        if (!str_type) return NULL;
        ltype = str2rdtype(str_type, NULL);
        if (ltype < 0)
            return NULL;
        add_bit_to_set(&bitmap, ltype);
    }
    if (!s)
        return NULL;
    if (!str_type) {
        return bitch("NSEC type list should not be empty");
    }
    rr->type_bitmap = compressed_set(&bitmap);
    G.dnssec_active = 1;

    return store_record(type, name, ttl, rr);
}

static char* nsec_human(struct rr *rrv)
{
    RRCAST(nsec);
    char ss[1024];
    char *s = ss;
    int l;
    char *base;
    int i, k;
    int type;
    char *type_name;

    l = snprintf(s, 1024, "%s", rr->next_domain);
    s += l;
    base = rr->type_bitmap.data;
    while (base - rr->type_bitmap.data < rr->type_bitmap.length) {
        for (i = 0; i < base[1]; i++) {
            for (k = 0; k <= 7; k++) {
                if (base[2+i] & (0x80 >> k)) {
                    type = ((unsigned char)base[0])*256 + i*8 + k;
                    type_name = rdtype2str(type);
                    l = snprintf(s, 1024-(s-ss), " %s", type_name);
                    s += l;
                }
            }
        }
        base += base[1]+2;
    }
    return quickstrdup_temp(ss);
}

static struct binary_data nsec_wirerdata(struct rr *rrv)
{
    RRCAST(nsec);

    return compose_binary_data("dd", 1,
        name2wire_name(rr->next_domain), rr->type_bitmap);
}

static void* nsec_validate(struct rr *rrv)
{
    RRCAST(nsec);
    struct named_rr *named_rr;

    named_rr = rr->rr.rr_set->named_rr;
    if (!check_typemap(rr->type_bitmap, named_rr, rrv))
        return NULL;

    return rr;
}

void validate_nsec_chain(void)
{
    struct rr_set *rr_set;
    struct named_rr *named_rr;

    rr_set = find_rr_set(T_NSEC, zone_apex);
    if (!rr_set) {
        named_rr = find_named_rr(zone_apex);
        moan(named_rr->file_name, named_rr->line, "apex NSEC not found");
        return;
    }
    while (1) {
        char name[1024];
        struct rr_nsec *rr = (struct rr_nsec *)rr_set->tail;
        char *s, *t;

        if (strcasecmp(rr->next_domain, zone_apex) == 0) /* chain complete */
            break;
        freeall_temp();
        s = rr->next_domain;
        t = name;
        while (*s) *t++ = tolower(*s++);
        *t = 0;
        rr_set = find_rr_set(T_NSEC, name);
        if (!rr_set) {
            moan(rr->rr.file_name, rr->rr.line, "broken NSEC chain %s -> %s",
                 rr->rr.rr_set->named_rr->name, rr->next_domain);
            break;
        }
    }
    freeall_temp();
}

struct rr_methods nsec_methods = { nsec_parse, nsec_human, nsec_wirerdata, NULL, nsec_validate };
