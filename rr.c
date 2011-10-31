/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <ctype.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <Judy.h>

#include "common.h"
#include "mempool.h"
#include "carp.h"
#include "textparse.h"
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
void *zone_data = NULL;
char *zone_apex = NULL;
int zone_apex_l = 0;

char *rdtype2str(int type)
{
	char s[10];
	if (type < 0 || type > 65535) {
		return "???";
	}
	if (type > T_MAX) {
		sprintf(s, "TYPE%d", type);
		return quickstrdup_temp(s);
	}
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

struct binary_data name2wire_name(char *s)
{
	unsigned char *res = getmem_temp(strlen(s)+2);
	unsigned char *r = res;
	unsigned char *c = res;
	struct binary_data toret;

	r++;
	*c = 0;
	while (*s) {
		if (*s != '.') {
			*r++ = *s++;
		} else {
			*c = (unsigned char)(r-c-1);
			c = r;
			*c = 0;
			r++;
			s++;
		}
	}
	*c = (unsigned char)(r-c-1);
	toret.length = r-res;
	toret.data = (char*)res;
	return toret;
}

static struct named_rr *find_or_create_named_rr(char *name)
{
	struct named_rr *named_rr = find_named_rr(name);

	if (!named_rr) {
		struct named_rr **named_rr_slot;
		char *s;

		named_rr = getmem(sizeof(struct named_rr));
		named_rr->name = quickstrdup(name);
		named_rr->rr_sets = NULL;
		named_rr->line = file_info->line;
		named_rr->file_name = file_info->name;
		named_rr->flags = 0;
		named_rr->parent = NULL;

		JSLI(named_rr_slot, zone_data, name2findable_name(name));
		if (named_rr_slot == PJERR)
			croak(2, "find_or_create_named_rr: JSLI failed");
		if (*named_rr_slot)
			croak(3, "find_or_create_named_rr: assertion error, %s should not be there", name);
		*named_rr_slot = named_rr;
		G.stats.names_count++;

		s = index(name, '.');
		if (s && s[1] != '\0') {
			named_rr->parent = find_or_create_named_rr(s+1);
		}
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

int name_belongs_to_zone(const char *name)
{
	int name_l;

	name_l = strlen(name);
	if (zone_apex && name_l >= zone_apex_l) {
		if (strcmp(zone_apex, name+name_l-zone_apex_l) != 0) {
			return 0;
		} else if (name_l > zone_apex_l && name[name_l-zone_apex_l-1] != '.') {
			return 0;
		}
	} else {
		if (zone_apex) {
			return 0;
		} else {
			// XXX this is actually very bad, zone apex is not know
			return 0;
		}
	}
	return 1;
}

struct rr *store_record(int rdtype, char *name, long ttl, void *rrptr)
{
	struct rr *rr = rrptr;
	struct named_rr *named_rr;
	struct rr_set *rr_set;
	int name_l;
	int apex_assigned = 0;

	name_l = strlen(name);
	if (name_l > 511)
		return bitch("name is too long: %s", name);

	if (G.stats.rr_count == 0) {
		if (rdtype != T_SOA) {
			return bitch("the first record in the zone must be an SOA record");
		} else {
			zone_apex = name;
			zone_apex_l = name_l;
			apex_assigned = 1;
		}
	}
	if (zone_apex && name_l >= zone_apex_l) {
		if (strcmp(zone_apex, name+name_l-zone_apex_l) != 0) {
			return bitch("%s does not belong to zone %s", name, zone_apex);
		} else if (name_l > zone_apex_l && name[name_l-zone_apex_l-1] != '.') {
			return bitch("%s does not belong to zone %s", name, zone_apex);
		}
	} else {
		if (zone_apex) {
			return bitch("%s does not belong to zone %s", name, zone_apex);
		} else {
			croakx(3, "assertion error: %s does not belong to a zone", name);
		}
	}

	named_rr = find_or_create_named_rr(name);
	if (apex_assigned) {
		named_rr->flags |= NAME_FLAG_APEX;
	}
	rr_set = find_or_create_rr_set(named_rr, rdtype);

	rr->rdtype = rdtype;
	rr->ttl = ttl;
	rr->line = file_info->line;
	rr->file_name = file_info->name;

	if (rr_set->count > 0) {
		rr_wire_func get_wired;
		struct binary_data new_d, old_d;
		struct rr *old_rr;

		if (rdtype > T_MAX)
			get_wired = any_wirerdata;
		else
			get_wired = rr_methods[rdtype].rr_wire;
		if (!get_wired) goto after_dup_check;
		new_d = get_wired(rr);
		if (new_d.length < 0) goto after_dup_check;
		old_rr = rr_set->tail;
		while (old_rr) {
			old_d = get_wired(old_rr);
			if (old_d.length == new_d.length &&
				memcmp(old_d.data, new_d.data, old_d.length) == 0)
			{
				G.stats.skipped_dup_rr_count++;
				return old_rr;
			}
			old_rr = old_rr->next;
		}
	}
after_dup_check:
	if (rdtype == T_SOA) {
	   	if (G.stats.soa_rr_count++) {
			return bitch("there could only be one SOA in a zone");
		}
	}

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
		char *rdata;
		if (rdtype > T_MAX)
			rdata = any_human(rr);
		else
			rdata = rr_methods[rdtype].rr_human(rr);
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
	named_rr->flags |= NAME_FLAG_HAS_RECORDS;

	return rr;
}

struct named_rr *find_named_rr(char *name)
{
	struct named_rr **named_rr_slot;

	JSLG(named_rr_slot, zone_data, name2findable_name(name));
	if (named_rr_slot)
		return *named_rr_slot;
	return NULL;
}

struct named_rr *find_next_named_rr(struct named_rr *named_rr)
{
	unsigned char sorted_name[512];
	struct named_rr **named_rr_p;

	strcpy((char*)sorted_name, (char*)name2findable_name(named_rr->name));
	JSLN(named_rr_p, zone_data, sorted_name);
	if (named_rr_p)
		return *named_rr_p;
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

uint32_t get_rr_set_count(struct named_rr *named_rr)
{
	uint32_t count;
	JLC(count, named_rr->rr_sets, 0, -1);
	return count;
}

static struct rr *unknown_parse(char *name, long ttl, int type, char *s)
{
	return bitch("unsupported resource record type %s", rdtype2str(type));
}

struct rr *rr_parse_any(char *name, long ttl, int type, char *s)
{
	struct rr_any *rr = getmem(sizeof(*rr));
	long long len;

	if (*s++ != '\\') {
invalid:
		return bitch("invalid custom type rdata");
	}
	if (*s++ != '#')
		goto invalid;
	if (*s && !isspace(*s) && *s != ';' && *s != ')')
		goto invalid;
	s = skip_white_space(s);
	if (!s)	return NULL;

	len = extract_integer(&s, "custom data size");
	if (len < 0) return NULL;
	if (len > 65535) goto invalid;

	rr->data = extract_hex_binary_data(&s, "custom data", EXTRACT_EAT_WHITESPACE);
	if (rr->data.length < 0)	return NULL;
	if (rr->data.length != len)
		return bitch("custom data is longer than specified");

	if (*s) {
		return bitch("garbage after valid %s data", rdtype2str(type));
	}

	return store_record(type, name, ttl, rr);
}

char* any_human(struct rr *rrv)
{
	RRCAST(any);
	char buf[80];

	sprintf(buf, "\\# %d ...", rr->data.length);
	return quickstrdup_temp(buf);
}

struct binary_data any_wirerdata(struct rr *rrv)
{
	RRCAST(any);

	return compose_binary_data("d", 1, rr->data);
}

static char* unknown_human(struct rr *rr)
{
	return NULL;
}

static struct binary_data unknown_wirerdata(struct rr *rr)
{
	bitch("not implemented wire rdata for rdtype %s", rdtype2str(rr->rdtype));
	return bad_binary_data();
}

struct rr_methods unknown_methods = { unknown_parse, unknown_human, unknown_wirerdata, NULL, NULL };

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
		break;
	case 'c':
		if (strcmp(rdtype, "cname") == 0) {
			return T_CNAME;
		}
		break;
	case 'd':
		if (strcmp(rdtype, "ds") == 0) {
			return T_DS;
		} else if (strcmp(rdtype, "dnskey") == 0) {
			return T_DNSKEY;
		}
		break;
	case 'h':
		if (strcmp(rdtype, "hinfo") == 0) {
			return T_HINFO;
		}
		break;
	case 'l':
		if (strcmp(rdtype, "loc") == 0) {
			return T_LOC;
		}
		break;
	case 'm':
		if (strcmp(rdtype, "mx") == 0) {
			return T_MX;
		}
		break;
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
		break;
	case 'p':
		if (strcmp(rdtype, "ptr") == 0) {
			return T_PTR;
		}
		break;
	case 'r':
		if (strcmp(rdtype, "rrsig") == 0) {
			return T_RRSIG;
		} else if (strcmp(rdtype, "rp") == 0) {
			return T_RP;
		}
		break;
	case 's':
		if (strcmp(rdtype, "soa") == 0) {
			return T_SOA;
		} else if (strcmp(rdtype, "srv") == 0) {
			return T_SRV;
		} else if (strcmp(rdtype, "sshfp") == 0) {
			return T_SSHFP;
		}
		break;
	case 't':
		if (strcmp(rdtype, "txt") == 0) {
			return T_TXT;
		} else if (strncmp(rdtype, "type", 4) == 0) {
			long type = strtol(rdtype+4, NULL, 10);
			if (type <= 0 || type > 65535)
				bitch("invalid rdtype %s", rdtype);
			return type;
		}
		break;
	}
	bitch("invalid or unsupported rdtype %s", rdtype);
	return -1;
}

void validate_rrset(struct rr_set *rr_set)
{
	struct rr *rr;
	int ttl;

	/* This can happen when rr_set was allocated but
	 * nothing was added to it due to an error. */
	if (rr_set->count == 0) return;
	rr = rr_set->tail;
	if (!rr) {
		croakx(4, "assertion failed: %s %s is null, but count is %d",
			   rdtype2str(rr_set->rdtype), rr_set->named_rr->name,
			   rr_set->count);
	}
	if (rr_set->rdtype < T_MAX && rr_methods[rr_set->rdtype].rr_validate_set)
		rr_methods[rr_set->rdtype].rr_validate_set(rr_set);
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
	int nsec3_present = 0;
	int nsec3_only = 1;

	if (named_rr->parent && (named_rr->parent->flags & (NAME_FLAG_DELEGATION|NAME_FLAG_NOT_AUTHORITATIVE)) != 0) {
		named_rr->flags |= NAME_FLAG_NOT_AUTHORITATIVE;
		if ((named_rr->flags & NAME_FLAG_HAS_RECORDS) != 0) {
			G.stats.not_authoritative++;
		}
	}
	rdtype = 0;
	JLF(rr_set_p, named_rr->rr_sets, rdtype);
	while (rr_set_p) {
		validate_rrset(*rr_set_p);
		if (rdtype == T_NSEC3)
			nsec3_present = 1;
		else if (rdtype != T_RRSIG)
			nsec3_only = 0;
		if ((named_rr->flags & NAME_FLAG_NOT_AUTHORITATIVE) == 0 &&
			rdtype != T_NS && rdtype != T_NSEC3 && rdtype != T_RRSIG)
		{
			struct named_rr *nrr = named_rr;
			while (nrr && (nrr->flags & NAME_FLAG_KIDS_WITH_RECORDS) == 0) {
				if ((nrr->flags & NAME_FLAG_APEX_PARENT) || strlen(nrr->name) < zone_apex_l) {
					nrr->flags |= NAME_FLAG_APEX_PARENT;
					break;
				}
				nrr->flags |= NAME_FLAG_KIDS_WITH_RECORDS;
				nrr = nrr->parent;
			}
		}
		if (rdtype == T_DS) {
			struct named_rr *nrr = named_rr;
			while (nrr && (nrr->flags & (NAME_FLAG_DELEGATION|NAME_FLAG_NOT_AUTHORITATIVE)) != 0) {
				// nrr->flags &= ~(NAME_FLAG_DELEGATION|NAME_FLAG_NOT_AUTHORITATIVE);
				nrr->flags |= NAME_FLAG_SIGNED_DELEGATION;
				nrr = nrr->parent;
			}
		}
		JLN(rr_set_p, named_rr->rr_sets, rdtype);
	}
	if (nsec3_present && nsec3_only) {
		named_rr->flags |= NAME_FLAG_NSEC3_ONLY;
	}
}


static void* nsec_validate_pass2(struct rr *rrv)
{
	RRCAST(nsec);
	struct named_rr *named_rr, *next_named_rr;

	named_rr = rr->rr.rr_set->named_rr;
	next_named_rr = find_next_named_rr(named_rr);
	/* Skip empty non-terminals and not authoritative records from consideration */
	while (next_named_rr) {
		if ((next_named_rr->flags & NAME_FLAG_HAS_RECORDS) == 0) {
			next_named_rr = find_next_named_rr(next_named_rr);
			continue;
		}
		if (next_named_rr->parent &&
			(next_named_rr->parent->flags & (NAME_FLAG_DELEGATION|NAME_FLAG_NOT_AUTHORITATIVE)) != 0)
		{
			named_rr->flags |= NAME_FLAG_NOT_AUTHORITATIVE;
			next_named_rr = find_next_named_rr(next_named_rr);
			continue;
		}
		break;
	}

	if (strcmp(rr->next_domain, zone_apex) == 0) {
		if (next_named_rr) {
			return moan(rr->rr.file_name, rr->rr.line, "NSEC says %s is the last name, but %s exists",
						named_rr->name, next_named_rr->name);
		}
	} else {
		if (!next_named_rr) {
			return moan(rr->rr.file_name, rr->rr.line, "NSEC says %s comes after %s, but nothing does",
						rr->next_domain, named_rr->name);
		} else if (strcmp(rr->next_domain, next_named_rr->name) != 0) {
			return moan(rr->rr.file_name, rr->rr.line, "NSEC says %s comes after %s, but %s does",
						rr->next_domain, named_rr->name, next_named_rr->name);
		}
	}

	/* TODO: more checks */
	return rr;
}

void second_validation_pass()
{
	unsigned char sorted_name[512];
	struct named_rr **named_rr_p;

	sorted_name[0] = 0;
	JSLF(named_rr_p, zone_data, sorted_name);
	while (named_rr_p) {
		struct rr_set **rr_set_p;

		freeall_temp();
		JLG(rr_set_p, (*named_rr_p)->rr_sets, T_NSEC);
		if (rr_set_p && (*rr_set_p)->tail) {
			nsec_validate_pass2((*rr_set_p)->tail);
		} else {
		}
		JSLN(named_rr_p, zone_data, sorted_name);
	}
}

void validate_zone(void)
{
	unsigned char sorted_name[512];
	struct named_rr **named_rr_p;

	sorted_name[0] = 0;
	JSLF(named_rr_p, zone_data, sorted_name);
	while (named_rr_p) {
		validate_named_rr(*named_rr_p);
		JSLN(named_rr_p, zone_data, sorted_name);
	}
	second_validation_pass();
}

void validate_record(struct rr *rr)
{
	freeall_temp();
	if (rr->rdtype < T_MAX && rr_methods[rr->rdtype].rr_validate)
		rr_methods[rr->rdtype].rr_validate(rr);
}

int extract_algorithm(char **s, char *what)
{
	int alg;
	char *str_alg;

	if (isdigit(**s)) {
		alg = extract_integer(s, what);
		if (algorithm_type(alg) == ALG_UNSUPPORTED) {
			bitch("bad or unsupported algorithm %d", alg);
			return ALG_UNSUPPORTED;
		}
		return alg;
	} else {
		str_alg = extract_label(s, what, "temporary");
		if (!str_alg) return ALG_UNSUPPORTED;
		if (strcmp(str_alg, "dsa") == 0)
			return ALG_DSA;
		if (strcmp(str_alg, "rsasha1") == 0)
			return ALG_RSASHA1;
		if (strcmp(str_alg, "dsa-nsec3-sha1") == 0)
			return ALG_DSA_NSEC3_SHA1;
		if (strcmp(str_alg, "rsasha1-nsec3-sha1") == 0)
			return ALG_RSASHA1_NSEC3_SHA1;
		if (strcmp(str_alg, "rsasha256") == 0)
			return ALG_RSASHA256;
		if (strcmp(str_alg, "rsasha512") == 0)
			return ALG_RSASHA512;
		if (strcmp(str_alg, "privatedns") == 0)
			return ALG_PRIVATEDNS;
		if (strcmp(str_alg, "privateoid") == 0)
			return ALG_PRIVATEOID;
		bitch("bad or unsupported algorithm %s", str_alg);
		return ALG_UNSUPPORTED;
	}
}

int algorithm_type(int alg)
{
	switch (alg) {
	case ALG_DSA:
		return ALG_DSA_FAMILY;
	case ALG_RSASHA1:
		return ALG_RSA_FAMILY;
	case ALG_DSA_NSEC3_SHA1:
		return ALG_DSA_FAMILY;
	case ALG_RSASHA1_NSEC3_SHA1:
		return ALG_RSA_FAMILY;
	case ALG_RSASHA256:
		return ALG_RSA_FAMILY;
	case ALG_RSASHA512:
		return ALG_RSA_FAMILY;
	case ALG_PRIVATEDNS:
		return ALG_PRIVATE_FAMILY;
	case ALG_PRIVATEOID:
		return ALG_PRIVATE_FAMILY;
	}
	return ALG_UNSUPPORTED;
}
