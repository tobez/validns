#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <Judy.h>

#include "carp.h"
#include "mempool.h"
#include "rr.h"

struct stats {
	int line_count;
	int rr_count;
	int rrset_count;
} stats;

Pvoid_t records = (Pvoid_t) NULL;

int
read_zone_file(FILE *);

/* ============== */

static int empty_line_or_comment(char *s)
{
	while (isspace(*s)) s++;
	if (!*s) return 1;
	if (*s == ';')	return 1;
	return 0;
}

static char *skip_white_space(char *s)
{
	while (isspace(*s)) s++;
	return s;
}

static char *extract_name(char *s, char *what)
{
	if (!(isalnum(*s) || *s == '_')) {
		carpx("%s expected at line %d", what, stats.line_count);
		return NULL;
	}
	s++;
	while (isalnum(*s) || *s == '.' || *s == '-' || *s == '_')
		s++;
	if (!isspace(*s)) {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	*s++ = '\0';
	return s;
}

static char *extract_integer(char *s, char *what, long *i)
{
	char *start = s;
	if (!isdigit(*s++)) {
		carpx("%s expected at line %d", what, stats.line_count);
		return NULL;
	}
	while (isdigit(*s)) s++;
	if (!isspace(*s)) {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	*s++ = '\0';
	*i = strtol(start, NULL, 10);
	return s;
}

static char *extract_alpha(char *s, char *what)
{
	if (!isalpha(*s++)) {
		carpx("%s expected at line %d", what, stats.line_count);
		return NULL;
	}
	while (isalpha(*s)) s++;
	if (!isspace(*s)) {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	*s++ = '\0';
	return s;
}

static char *extract_alnum(char *s, char *what)
{
	if (!isalnum(*s++)) {
		carpx("%s expected at line %d", what, stats.line_count);
		return NULL;
	}
	while (isalnum(*s)) s++;
	if (!isspace(*s)) {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	*s++ = '\0';
	return s;
}

static char *extract_ip(char *s, char *what, unsigned *ipptr)
{
	unsigned octet = 0;
	unsigned ip = 0;
	if (!isdigit(*s)) {
		carpx("%s expected at line %d", what, stats.line_count);
		return NULL;
	}
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	s++;
	if (!isdigit(*s)) {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	s++;
	if (!isdigit(*s)) {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	s++;
	if (!isdigit(*s)) {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	ip = 256*ip + octet;
	*ipptr = ip;

	if (!isspace(*s)) {
		carpx("%s not valid at line %d", what, stats.line_count);
		return NULL;
	}
	*s++ = '\0';
	return s;
}

static void store_record(char *name, void *rrptr)
{
	struct rr *rr = rrptr;
	struct rr **chain;

	rr->next = NULL;
	JSLI(chain, records, (unsigned char*)name);
	if (chain == PJERR)
		croak(1, "store_record/JSLI at line %d", stats.line_count);
	if (*chain) {
		rr->next = *chain;
	} else {
		stats.rrset_count++;
	}
	stats.rr_count++;
	*chain = rr;
}

/* Dangerous macros, make assumption about vars in the frame and what they are */
#define GETNAME(var) { next = extract_name(s, #var); if (!next) return NULL; var = s; s = next; next = skip_white_space(s); s = next; }
#define GETINT(var) { next = extract_integer(s, #var, &var); if (!next) return NULL; s = next; next = skip_white_space(s); s = next; }
#define GETIP(var) { next = extract_ip(s, #var, &var); if (!next) return NULL; s = next; next = skip_white_space(s); s = next; }

static void* parse_soa(char *name, long ttl, char *s)
{
	char *next, *end;
	char *mname, *rname;
	long serial, refresh, retry, expire, minimum;
	struct rr_soa *rr;

	GETNAME(mname);
	GETNAME(rname);
	GETINT(serial);
	GETINT(refresh);
	GETINT(retry);
	GETINT(expire);
	GETINT(minimum);
	if (*s) {
		carpx("garbage after valid SOA at line %d", stats.line_count);
		return NULL;
	}

	rr = getmem(sizeof(*rr) + strlen(mname) + 1 + strlen(rname) + 1);
	rr->rr.ttl    = ttl;
	rr->rr.rdtype = T_SOA;
	rr->serial    = serial;
	rr->refresh   = refresh;
	rr->retry     = retry;
	rr->expire    = expire;
	rr->minimum   = minimum;
	end = stpcpy(rr->mname, mname) + 1;
	strcpy(end, rname);
	rr->rname = end;
	store_record(name, rr);
	return rr;
}

static void *parse_rrsig(char *name, long ttl, char *s)
{
	struct rr_rrsig *rr;
	/* XXX */
	return rr;
}

static void *parse_srv(char *name, long ttl, char *s)
{
	struct rr_srv *rr;
	/* XXX */
	return rr;
}

static void *parse_cname(char *name, long ttl, char *s)
{
	char *next;
	char *cname;
	struct rr_cname *rr;

	GETNAME(cname);
	if (*s) {
		carpx("garbage after valid CNAME at line %d", stats.line_count);
		return NULL;
	}

	rr = getmem(sizeof(*rr) + strlen(cname) + 1);
	rr->rr.ttl    = ttl;
	rr->rr.rdtype = T_CNAME;
	strcpy(rr->cname, cname);
	store_record(name, rr);
	return rr;
}

static void *parse_aaaa(char *name, long ttl, char *s)
{
	struct rr_aaaa *rr;
	/* XXX */
	return rr;
}

static void *parse_mx(char *name, long ttl, char *s)
{
	char *next;
	long preference;
	char *exchange;
	struct rr_mx *rr;

	GETINT(preference);
	GETNAME(exchange);
	if (*s) {
		carpx("garbage after valid MX at line %d", stats.line_count);
		return NULL;
	}
	/* XXX */
	return rr;
}

static void *parse_ns(char *name, long ttl, char *s)
{
	char *next;
	char *nsdname;
	struct rr_ns *rr;

	GETNAME(nsdname);
	if (*s) {
		carpx("garbage after valid NS at line %d", stats.line_count);
		return NULL;
	}

	rr = getmem(sizeof(*rr) + strlen(nsdname) + 1);
	rr->rr.ttl    = ttl;
	rr->rr.rdtype = T_NS;
	strcpy(rr->nsdname, nsdname);
	store_record(name, rr);
	return rr;
}

static void *parse_txt(char *name, long ttl, char *s)
{
	struct rr_txt *rr;
	/* XXX */
	return rr;
}

static void *parse_naptr(char *name, long ttl, char *s)
{
	struct rr_naptr *rr;
	/* XXX */
	return rr;
}

static void *parse_nsec3(char *name, long ttl, char *s)
{
	struct rr_nsec3 *rr;
	/* XXX */
	return rr;
}

static void *parse_nsec3param(char *name, long ttl, char *s)
{
	struct rr_nsec3param *rr;
	/* XXX */
	return rr;
}

static void *parse_dnskey(char *name, long ttl, char *s)
{
	char *next;
	struct rr_dnskey *rr;
	long flags, proto, algorithm;

	GETINT(flags);
	if (flags != 256 && flags != 257) {
		carpx("Wrong flags in DNSKEY at line %d", stats.line_count);
		return NULL;
	}
	GETINT(proto);
	if (proto != 3) {
		carpx("Unrecognized protocol in DNSKEY at line %d", stats.line_count);
		return NULL;
	}
	GETINT(algorithm);
	if (algorithm != 8) {
		carpx("Unsupported algorithm #%d in DNSKEY at line %d", algorithm, stats.line_count);
		return NULL;
	}

	if (*s) {
		carpx("garbage after otherwise valid DNSKEY at line %d", stats.line_count);
		return NULL;
	}

	/* XXX */
	return rr;
}

static void *parse_a(char *name, long ttl, char *s)
{
	char *next;
	unsigned address;
	struct rr_a *rr;

	GETIP(address);
	if (*s) {
		carpx("garbage after valid A at line %d", stats.line_count);
		return NULL;
	}

	/* XXX */
	return rr;
}

int
read_zone_file(FILE *stream)
{
	char buf[2048];
	char *next, *s;
	char *name, *class, *rdtype;
	long ttl;
	while (fgets(buf, 2048, stream)) {
		stats.line_count++;
		if (empty_line_or_comment(buf))
			continue;

		s = buf;
		next = skip_white_space(s);
		s = next;

		next = extract_name(s, "record name");
		if (!next)	continue;
		name = s;
		while (*s) {
			*s = tolower(*s);
			s++;
		}
		s = next;
		next = skip_white_space(s);
		s = next;

		next = extract_integer(s, "TTL", &ttl);
		if (!next)	continue;
		s = next;
		next = skip_white_space(s);
		s = next;

		next = extract_alpha(s, "class");
		if (!next)	continue;
		class = s;
		if (strcasecmp(class, "in") != 0) {
			carpx("unsupported class: %s at line %d", class, stats.line_count);
			continue;
		}
		s = next;
		next = skip_white_space(s);
		s = next;

		next = extract_alnum(s, "rdtype");
		if (!next)	continue;
		rdtype = s;
		while (*s) {
			*s = toupper(*s);
			s++;
		}
		s = next;
		next = skip_white_space(s);
		s = next;

		switch (*rdtype) {
		case 'A':
			if (strcmp(rdtype, "A") == 0) {
				parse_a(name, ttl, s);
				break;
			} else if (strcmp(rdtype, "AAAA") == 0) {
				parse_aaaa(name, ttl, s);
				break;
			}
		case 'C':
			if (strcmp(rdtype, "CNAME") == 0) {
				parse_cname(name, ttl, s);
				break;
			}
		case 'D':
			if (strcmp(rdtype, "DNSKEY") == 0) {
				parse_dnskey(name, ttl, s);
				break;
			}
		case 'M':
			if (strcmp(rdtype, "MX") == 0) {
				parse_mx(name, ttl, s);
				break;
			}
		case 'N':
			if (strcmp(rdtype, "NS") == 0) {
				parse_ns(name, ttl, s);
				break;
			} else if (strcmp(rdtype, "NAPTR") == 0) {
				parse_naptr(name, ttl, s);
				break;
			} else if (strcmp(rdtype, "NSEC3") == 0) {
				parse_nsec3(name, ttl, s);
				break;
			} else if (strcmp(rdtype, "NSEC3PARAM") == 0) {
				parse_nsec3param(name, ttl, s);
				break;
			}
		case 'R':
			if (strcmp(rdtype, "RRSIG") == 0) {
				parse_rrsig(name, ttl, s);
				break;
			}
		case 'S':
			if (strcmp(rdtype, "SOA") == 0) {
				parse_soa(name, ttl, s);
				break;
			} else if (strcmp(rdtype, "SRV") == 0) {
				parse_srv(name, ttl, s);
				break;
			}
		case 'T':
			if (strcmp(rdtype, "TXT") == 0) {
				parse_txt(name, ttl, s);
				break;
			}
		default:
			carpx("invalid or unsupported rdtype: %s at line %d", rdtype, stats.line_count);
		}
	}
	if (ferror(stream))
		croak(1, "read error");
	return 0;
}

int
main(void)
{
	bzero(&stats, sizeof(stats));
	read_zone_file(stdin);
	printf("lines processed:   %d\n", stats.line_count);
	printf("records found:     %d\n", stats.rr_count);
	printf("record sets found: %d\n", stats.rrset_count);
	return 0;
}
