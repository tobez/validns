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
void *zone = NULL;

char *rdtype2str(int type)
{
	if (type < 0 || type > T_MAX)
		return "???";
	return rdtype2str_map[type];
}

static unsigned char *name2findable_name(char *s)
{
	int l = strlen(s);
	unsigned char *res = getmem_temp(l+1);
	unsigned char *r = res;
	int i;

	if (l > 0 && s[l-1] == '.')
		l--;
	while (--l >= 0) {
		i = l;
		while (i >= 0 && s[i] != '.')
			i--;
		memcpy(r, s+i+1, l-i);
		r += l-i;
		*r = '\x01';
		r++;
		l = i;
	}
	if (r > res)    r--;
	*r = 0;
	return res;
}

static struct named_rr *find_or_create_named_rr(char *name)
{
	struct named_rr *named_rr = find_named_rr(name);

	if (!named_rr) {
		struct named_rr **named_rr_slot;

		named_rr = getmem(sizeof(struct named_rr));
		named_rr->name = quickstrdup(name);
		named_rr->rr_sets = NULL;
		named_rr->line = file_info->line;
		named_rr->file_name = file_info->name;

		JSLI(named_rr_slot, zone, name2findable_name(name));
		if (named_rr_slot == PJERR)
			croak(2, "find_or_create_named_rr: JSLI failed");
		if (*named_rr_slot)
			croak(3, "find_or_create_named_rr: assertion error, %s should not be there", name);
		*named_rr_slot = named_rr;
		G.stats.names_count++;
	}

	return named_rr;
}

static struct rr_set *find_or_create_rr_set(struct named_rr *named_rr, int rdtype)
{
	struct rr_set *rr_set = find_rr_set_in_named_rr(named_rr, rdtype);
	if (!rr_set) {
		struct rr_set **rr_set_slot;

		rr_set = getmem(sizeof(struct rr_set));
		rr_set->head = NULL;
		rr_set->tail = NULL;
		rr_set->named_rr = named_rr;
		rr_set->rdtype = rdtype;
		rr_set->count = 0;

		JLI(rr_set_slot, named_rr->rr_sets, rdtype);
		if (rr_set_slot == PJERR)
			croak(2, "find_or_create_rr_set: JLI failed");
		if (*rr_set_slot)
			croak(3, "find_or_create_rr_set: assertion error, %s/%s should not be there",
				  named_rr->name, rdtype2str(rdtype));
		*rr_set_slot = rr_set;
		G.stats.rrset_count++;
	}
	return rr_set;
}

void *store_record(int rdtype, char *name, long ttl, void *rrptr)
{
	struct rr *rr = rrptr;
	struct named_rr *named_rr;
	struct rr_set *rr_set;

	if (strlen(name) > 511)
		return bitch("name is too long: %s", name);

	if (G.stats.rr_count == 0) {
		if (rdtype != T_SOA) {
			return bitch("the first record in the zone must be an SOA record");
		}
	}

	named_rr = find_or_create_named_rr(name);
	rr_set = find_or_create_rr_set(named_rr, rdtype);

	rr->rdtype = rdtype;
	rr->ttl = ttl;
	rr->line = file_info->line;
	rr->file_name = file_info->name;
	rr->rr_set = rr_set;

	rr->next = NULL;
	rr->prev = rr_set->head;
	rr_set->head = rr;
	if (rr->prev)
		rr->prev->next = rr;
	if (!rr_set->tail)
		rr_set->tail = rr;

	rr_set->count++;

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

	G.stats.rr_count++;

	return rr;
}

struct named_rr *find_named_rr(char *name)
{
	struct named_rr **named_rr_slot;

	JSLG(named_rr_slot, zone, name2findable_name(name));
	if (named_rr_slot)
		return *named_rr_slot;
	return NULL;
}

struct rr_set *find_rr_set(int rdtype, char *name)
{
	struct named_rr *named_rr;

	named_rr = find_named_rr(name);
	if (!named_rr)
		return NULL;

	return find_rr_set_in_named_rr(named_rr, rdtype);
}

struct rr_set *find_rr_set_in_named_rr(struct named_rr *named_rr, int rdtype)
{
	struct rr_set **rr_set_slot;

	JLG(rr_set_slot, named_rr->rr_sets, rdtype);
	if (rr_set_slot)
		return *rr_set_slot;
	return NULL;
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

void validate_rrset(struct rr_set *rr_set)
{
	struct rr *rr;
	int ttl;

	rr = rr_set->tail;
	if (rr_set->rdtype == T_NS && rr_set->count < 2) {
		moan(rr->file_name, rr->line, "there should be at least two NS records per name");
	}
	ttl = rr->ttl;

	while (rr) {
		validate_record(rr);
		if (ttl != rr->ttl) {
		   	if (rr->rdtype != T_RRSIG) /* RRSIG is an exception */
				moan(rr->file_name, rr->line, "TTL values differ within an RR set");
		}
		rr = rr->next;
	}
}

void validate_named_rr(struct named_rr *named_rr)
{
	Word_t rdtype;
	struct rr_set **rr_set_p;

	rdtype = 0;
	JLF(rr_set_p, named_rr->rr_sets, rdtype);
	while (rr_set_p) {
		validate_rrset(*rr_set_p);
		JLN(rr_set_p, named_rr->rr_sets, rdtype);
	}
}

void validate_zone(void)
{
	unsigned char sorted_name[512];
	struct named_rr **named_rr_p;

	sorted_name[0] = 0;
	JSLF(named_rr_p, zone, sorted_name);
	while (named_rr_p) {
		validate_named_rr(*named_rr_p);
		JSLN(named_rr_p, zone, sorted_name);
	}
}

void validate_record(struct rr *rr)
{
	freeall_temp();
}

