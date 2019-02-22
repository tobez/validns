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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr *ipseckey_parse(char *name, long ttl, int type, char *s)
{
    struct rr_ipseckey *rr = getmem(sizeof(*rr));
    int i;

    rr->precedence = i = extract_integer(&s, "precedence", NULL);
    if (i < 0)    return NULL;
    if (i >= 256) return bitch("precedence range is not valid");

    rr->gateway_type = i = extract_integer(&s, "gateway type", NULL);
    if (i < 0) return NULL;
    if (i > 3) return bitch("gateway type is not valid");

    rr->algorithm = i = extract_integer(&s, "algorithm", NULL);
    if (i < 0) return NULL;
    if (i > 2) return bitch("algorithm is not valid");

    switch (rr->gateway_type) {
    case 0:
        rr->gateway.gateway_none = extract_name(&s, "gateway/.", KEEP_CAPITALIZATION);
        if (!rr->gateway.gateway_none) return NULL;
        if (strcmp(rr->gateway.gateway_none, ".") != 0)
            return bitch("gateway must be \".\" for gateway type 0");
        break;
    case 1:
        if (extract_ipv4(&s, "gateway/IPv4", &rr->gateway.gateway_ipv4) <= 0)
            return NULL;
        break;
    case 2:
        if (extract_ipv6(&s, "gateway/IPv6", &rr->gateway.gateway_ipv6) <= 0)
            return NULL;
        break;
    case 3:
        rr->gateway.gateway_name = extract_name(&s, "gateway/name", KEEP_CAPITALIZATION);
        if (!rr->gateway.gateway_name) return NULL;
        break;
    default:
        croakx(7, "assertion failed: gateway type %d not within range", rr->gateway_type);
    }

    /* My reading of http://tools.ietf.org/html/rfc4025 is fuzzy on:
     *
     * - whether it is possible to have algorithm 0 and non-empty key;
     * - whether it is possible to have empty key and algorithm != 0.
     *
     * Here I assume "not possible" for both.
     */
    switch (rr->algorithm) {
    case 0:
        break;
    case 1:
        /* DSA key */
        rr->public_key = extract_base64_binary_data(&s, "public key");
        if (rr->public_key.length < 0)     return NULL;
        break;
    case 2:
        /* RSA key */
        rr->public_key = extract_base64_binary_data(&s, "public key");
        if (rr->public_key.length < 0)     return NULL;
        break;
    default:
        croakx(7, "assertion failed: algorithm %d not within range", rr->algorithm);
    }

    if (*s) {
        return bitch("garbage after valid IPSECKEY data");
    }

    return store_record(type, name, ttl, rr);
}

static char* ipseckey_human(struct rr *rrv)
{
    RRCAST(ipseckey);
    char s[1024], gw[1000];

    switch (rr->gateway_type) {
    case 0:
        strcpy(gw, rr->gateway.gateway_none);
        break;
    case 1:
        inet_ntop(AF_INET, &rr->gateway.gateway_ipv4, gw, sizeof(gw));
        break;
    case 2:
        inet_ntop(AF_INET6, &rr->gateway.gateway_ipv6, gw, sizeof(gw));
        break;
    case 3:
        strcpy(gw, rr->gateway.gateway_name);
        break;
    default:
        strcpy(gw, "??");
    }
    snprintf(s, 1024, "( %d %d %d %s ... )",
         rr->precedence, rr->gateway_type, rr->algorithm, gw);
    return quickstrdup_temp(s);
}

static struct binary_data ipseckey_wirerdata(struct rr *rrv)
{
    RRCAST(ipseckey);
    struct binary_data helper;

    switch (rr->gateway_type) {
    case 0:
        if (rr->algorithm != 0)
            return compose_binary_data("111d", 1,
                rr->precedence, rr->gateway_type, rr->algorithm,
                rr->public_key);
        else
            return compose_binary_data("111", 1,
                rr->precedence, rr->gateway_type, rr->algorithm);
        break;
    case 1:
        helper.length = sizeof(rr->gateway.gateway_ipv4);
        helper.data = (void *)&rr->gateway.gateway_ipv4;

        if (rr->algorithm != 0)
            return compose_binary_data("111dd", 1,
                rr->precedence, rr->gateway_type, rr->algorithm,
                helper,
                rr->public_key);
        else
            return compose_binary_data("111d", 1,
                rr->precedence, rr->gateway_type, rr->algorithm,
                helper);
        break;
    case 2:

        helper.length = sizeof(rr->gateway.gateway_ipv6);
        helper.data = (void *)&rr->gateway.gateway_ipv6;

        if (rr->algorithm != 0)
            return compose_binary_data("111dd", 1,
                rr->precedence, rr->gateway_type, rr->algorithm,
                helper,
                rr->public_key);
        else
            return compose_binary_data("111d", 1,
                rr->precedence, rr->gateway_type, rr->algorithm,
                helper);
        break;
    case 3:
        if (rr->algorithm != 0)
            return compose_binary_data("111dd", 1,
                rr->precedence, rr->gateway_type, rr->algorithm,
                name2wire_name(rr->gateway.gateway_name),
                rr->public_key);
        else
            return compose_binary_data("111d", 1,
                rr->precedence, rr->gateway_type, rr->algorithm,
                name2wire_name(rr->gateway.gateway_name));
        break;
    }
    return bad_binary_data();
}

struct rr_methods ipseckey_methods = { ipseckey_parse, ipseckey_human, ipseckey_wirerdata, NULL, NULL };

