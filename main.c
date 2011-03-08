#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <Judy.h>

#include "carp.h"

struct stats {
	int line_count;
	int rr_count;
	int rrset_count;
} stats;

Pvoid_t records = (Pvoid_t) NULL;

#define T_A		1
#define T_NS	2
#define T_CNAME	5
#define T_SOA	6
#define T_MX	15
#define T_TXT	16
#define T_AAAA	28
#define T_SRV	33
#define T_NAPTR	35
#define T_RRSIG	46
#define T_DNSKEY	48
#define T_NSEC3	50
#define T_NSEC3PARAM	51

struct rr
{
	struct rr* next;
	int	ttl;
	int rdtype;
};

struct rr_a
{
	struct rr rr;
	/* XXX */
};

struct rr_soa
{
	struct rr rr;
	int serial, refresh, retry, expire, minimum;
	char *rname;
	char mname[0];
};

struct rr_ns
{
	struct rr rr;
	/* XXX */
};

struct rr_txt
{
	struct rr rr;
	/* XXX */
};

struct rr_naptr
{
	struct rr rr;
	/* XXX */
};

struct rr_nsec3
{
	struct rr rr;
	/* XXX */
};

struct rr_nsec3param
{
	struct rr rr;
	/* XXX */
};

struct rr_rrsig
{
	struct rr rr;
	/* XXX */
};

struct rr_srv
{
	struct rr rr;
	/* XXX */
};

struct rr_cname
{
	struct rr rr;
	/* XXX */
};

struct rr_aaaa
{
	struct rr rr;
	/* XXX */
};

struct rr_mx
{
	struct rr rr;
	/* XXX */
};

struct rr_dnskey
{
	struct rr rr;
	/* XXX */
};

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
	if (!(isalnum(*s) || *s == '_'))
		croakx(0, "%s expected at line %d", what, stats.line_count);
	s++;
	while (isalnum(*s) || *s == '.' || *s == '-' || *s == '_')
		s++;
	if (!isspace(*s))
		croakx(0, "%s not valid at line %d", what, stats.line_count);
	*s++ = '\0';
	return s;
}

static char *extract_integer(char *s, char *what, long *i)
{
	char *start = s;
	if (!isdigit(*s++))
		croakx(0, "%s expected at line %d", what, stats.line_count);
	while (isdigit(*s)) s++;
	if (!isspace(*s))
		croakx(0, "%s not valid at line %d", what, stats.line_count);
	*s++ = '\0';
	*i = strtol(start, NULL, 10);
	return s;
}

static char *extract_alpha(char *s, char *what)
{
	if (!isalpha(*s++))
		croakx(0, "%s expected at line %d", what, stats.line_count);
	while (isalpha(*s)) s++;
	if (!isspace(*s))
		croakx(0, "%s not valid at line %d", what, stats.line_count);
	*s++ = '\0';
	return s;
}

static char *extract_alnum(char *s, char *what)
{
	if (!isalnum(*s++))
		croakx(0, "%s expected at line %d", what, stats.line_count);
	while (isalnum(*s)) s++;
	if (!isspace(*s))
		croakx(0, "%s not valid at line %d", what, stats.line_count);
	*s++ = '\0';
	return s;
}

static char *extract_ip(char *s, char *what, unsigned *ipptr)
{
	unsigned octet = 0;
	unsigned ip = 0;
	if (!isdigit(*s))
		croakx(0, "%s expected at line %d", what, stats.line_count);
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.')
		croakx(0, "%s not valid at line %d", what, stats.line_count);
	s++;
	if (!isdigit(*s))
		croakx(0, "%s not valid at line %d", what, stats.line_count);
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.')
		croakx(0, "%s not valid at line %d", what, stats.line_count);
	s++;
	if (!isdigit(*s))
		croakx(0, "%s not valid at line %d", what, stats.line_count);
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.')
		croakx(0, "%s not valid at line %d", what, stats.line_count);
	s++;
	if (!isdigit(*s))
		croakx(0, "%s not valid at line %d", what, stats.line_count);
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	ip = 256*ip + octet;
	*ipptr = ip;

	if (!isspace(*s))
		croakx(0, "%s not valid at line %d", what, stats.line_count);
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
#define GETNAME(var) { next = extract_name(s, #var); var = s; s = next; next = skip_white_space(s); s = next; }
#define GETINT(var) { next = extract_integer(s, #var, &var); s = next; next = skip_white_space(s); s = next; }
#define GETIP(var) { next = extract_ip(s, #var, &var); s = next; next = skip_white_space(s); s = next; }

static void parse_soa(char *name, long ttl, char *s)
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
	if (*s)
		croakx(1, "garbage after valid SOA at line %d", stats.line_count);

	rr = malloc(sizeof(*rr) + strlen(mname) + 1 + strlen(rname) + 1);
	if (!rr)
		croak(1, "malloc rr_soa");
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
}

static void parse_rrsig(char *name, long ttl, char *s)
{
	struct rr_rrsig *rr;
	/* XXX */
}

static void parse_srv(char *name, long ttl, char *s)
{
	struct rr_srv *rr;
	/* XXX */
}

static void parse_cname(char *name, long ttl, char *s)
{
	char *next;
	char *cname;
	struct rr_cname *rr;

	GETNAME(cname);
	if (*s)
		croakx(1, "garbage after valid CNAME at line %d", stats.line_count);
	/* XXX */
}

static void parse_aaaa(char *name, long ttl, char *s)
{
	struct rr_aaaa *rr;
	/* XXX */
}

static void parse_mx(char *name, long ttl, char *s)
{
	char *next;
	long preference;
	char *exchange;
	struct rr_mx *rr;

	GETINT(preference);
	GETNAME(exchange);
	if (*s)
		croakx(1, "garbage after valid MX at line %d", stats.line_count);
	/* XXX */
}

static void parse_ns(char *name, long ttl, char *s)
{
	struct rr_ns *rr;
	/* XXX */
}

static void parse_txt(char *name, long ttl, char *s)
{
	struct rr_txt *rr;
	/* XXX */
}

static void parse_naptr(char *name, long ttl, char *s)
{
	struct rr_naptr *rr;
	/* XXX */
}

static void parse_nsec3(char *name, long ttl, char *s)
{
	struct rr_nsec3 *rr;
	/* XXX */
}

static void parse_nsec3param(char *name, long ttl, char *s)
{
	struct rr_nsec3param *rr;
	/* XXX */
}

static void parse_dnskey(char *name, long ttl, char *s)
{
	struct rr_dnskey *rr;
	/* XXX */
}

static void parse_a(char *name, long ttl, char *s)
{
	char *next;
	unsigned address;
	struct rr_a *rr;

	GETIP(address);
	if (*s)
		croakx(1, "garbage after valid A at line %d", stats.line_count);
	/* XXX */
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
		name = s;
		while (*s) {
			*s = tolower(*s);
			s++;
		}
		s = next;
		next = skip_white_space(s);
		s = next;

		next = extract_integer(s, "TTL", &ttl);
		s = next;
		next = skip_white_space(s);
		s = next;

		next = extract_alpha(s, "class");
		class = s;
		if (strcasecmp(class, "in") != 0)
			croakx(1, "unsupported class: %s at line %d", class, stats.line_count);
		s = next;
		next = skip_white_space(s);
		s = next;

		next = extract_alnum(s, "rdtype");
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
			croakx(1, "invalid or unsupported rdtype: %s at line %d", rdtype, stats.line_count);
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
