/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <Judy.h>

#include "common.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static char* rdtype2str_map[T_MAX+1] = {
	"0",
	"A",
	"NS",
	"MD",
	"MF",
	"CNAME", /* 5 */
	"SOA",
	"MB",
	"MG",
	"MR",
	"NULL", /* 10 */
	"WKS",
	"PTR",
	"HINFO",
	"MINFO",
	"MX",  /* 15 */
	"TXT", 
	"RP",
	"AFSDB",
	"X25",
	"ISDN", /* 20 */
	"RT",
	"NSAP",
	"NSAP-PTR",
	"SIG",
	"KEY",  /* 25 */
	"PX",
	"GPOS",
	"AAAA",
	"LOC",
	"NXT",  /* 30 */
	"EID",
	"NIMLOC",
	"SRV",
	"ATMA",
	"NAPTR", /* 35 */
	"KX",
	"CERT",
	"A6",
	"DNAME",
	"SINK", /* 40 */
	"OPT",
	"APL",
	"DS",
	"SSHFP",
	"IPSECKEY", /* 45 */
	"RRSIG",
	"NSEC",
	"DNSKEY",
	"DHCID",
	"NSEC3", /* 50 */
	"NSEC3PARAM"
};
void *records = NULL;

char *rdtype2str(int type)
{
	if (type < 0 || type > T_MAX)
		return "???";
	return rdtype2str_map[type];
}

void *store_record(int rdtype, char *name, long ttl, void *rrptr)
{
	struct rr *rr = rrptr;
	struct rr **chain;

	rr->rdtype = rdtype;
	rr->ttl = ttl;
	rr->line = file_info->line;
	rr->file_name = file_info->name;
	rr->next = NULL;

	if (G.opt.verbose) {
		char *rdata = rr_methods[rdtype].rr_human(rr);
		fprintf(stderr, "-> %s:%d: %s IN %ld %s",
				file_info->name, file_info->line,
				name, ttl, rdtype2str(rdtype));
		if (rdata) {
			fprintf(stderr, " %s\n", rdata);
		} else {
			fprintf(stderr, "\n");
		}
	}

	JSLI(chain, records, (unsigned char*)name);
	if (chain == PJERR)
		croak(1, "store_record/JSLI");
	if (*chain) {
		rr->next = *chain;
	} else {
		G.stats.rrset_count++;
	}
	G.stats.rr_count++;
	*chain = rr;

	return rr;
}

static void* unknown_parse(char *name, long ttl, int type, char *s)
{
	return bitch("unsupported resource record type %s", rdtype2str(type));
}

static char* unknown_human(void *rrv)
{
	return NULL;
}

static void* unknown_wirerdata(void *rrv)
{
	struct rr *rr = rrv;
	return bitch("not implemented wire rdata for rdtype %d", rr->rdtype);
}

struct rr_methods unknown_methods = { unknown_parse, unknown_human, unknown_wirerdata };

int str2rdtype(char *rdtype)
{
	if (!rdtype) return -1;
	switch (*rdtype) {
	case 'a':
		if (strcmp(rdtype, "a") == 0) {
			return T_A;
		} else if (strcmp(rdtype, "aaaa") == 0) {
			return T_AAAA;
		}
	case 'c':
		if (strcmp(rdtype, "cname") == 0) {
			return T_CNAME;
		}
	case 'd':
		if (strcmp(rdtype, "dnskey") == 0) {
			return T_DNSKEY;
		}
	case 'm':
		if (strcmp(rdtype, "mx") == 0) {
			return T_MX;
		}
	case 'n':
		if (strcmp(rdtype, "ns") == 0) {
			return T_NS;
		} else if (strcmp(rdtype, "naptr") == 0) {
			return T_NAPTR;
		} else if (strcmp(rdtype, "nsec") == 0) {
			return T_NSEC;
		} else if (strcmp(rdtype, "nsec3") == 0) {
			return T_NSEC3;
		} else if (strcmp(rdtype, "nsec3param") == 0) {
			return T_NSEC3PARAM;
		}
	case 'r':
		if (strcmp(rdtype, "rrsig") == 0) {
			return T_RRSIG;
		}
	case 's':
		if (strcmp(rdtype, "soa") == 0) {
			return T_SOA;
		} else if (strcmp(rdtype, "srv") == 0) {
			return T_SRV;
		}
	case 't':
		if (strcmp(rdtype, "txt") == 0) {
			return T_TXT;
		}
	}
	bitch("invalid or unsupported rdtype %s", rdtype);
	return -1;
}

