#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <Judy.h>

#include "common.h"
#include "carp.h"
#include "mempool.h"
#include "rr.h"

struct globals G;
struct file_info *file_info = NULL;

Pvoid_t records = (Pvoid_t) NULL;

int
read_zone_file(void);

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
	if (*s == ';') {
		while (*s) s++;
	}
	return s;
}

static char *extract_name(char **input, char *what)
{
	char *s = *input;
	char *r = NULL;
	char *end = NULL;

	if (*s == '@') {
		s++;
		if (*s && !isspace(*s)) {
			return bitch("literal @ in %s is not all by itself", what);
		}
		if (!G.opt.current_origin) {
			return bitch("do not know origin to expand @ in %s", what);
		}
		r = quickstrdup(G.opt.current_origin);
	} else {
		if (!(isalnum(*s) || *s == '_')) {
			return bitch("%s expected", what);
		}
		s++;
		while (isalnum(*s) || *s == '.' || *s == '-' || *s == '_')
			s++;
		if (*s && !isspace(*s)) {
			return bitch("%s is not valid", what);
		}
		if (!*s)	end = s;
		*s++ = '\0';
		if (*(s-2) == '.') {
			r = quickstrdup(*input);
		} else {
			if (!G.opt.current_origin) {
				return bitch("do not know origin to determine %s", what);
			}
			r = getmem(strlen(*input) + 1 + strlen(G.opt.current_origin) + 1);
			strcpy(stpcpy(stpcpy(r, *input), "."), G.opt.current_origin);
		}
	}
	if (end) {
		*input = end;
	} else {
		*input = skip_white_space(s);
	}
	s = r;
	while (*s) {
		*s = tolower(*s);
		s++;
	}
	return r;
}

static char *extract_integer(char *s, char *what, long *i)
{
	char *start = s;
	if (!isdigit(*s++)) {
		return bitch("%s expected", what);
	}
	while (isdigit(*s)) s++;
	if (!isspace(*s)) {
		return bitch("%s is not valid", what);
	}
	*s++ = '\0';
	*i = strtol(start, NULL, 10);
	return s;
}

static char *extract_alpha(char *s, char *what)
{
	if (!isalpha(*s++)) {
		return bitch("%s expected", what);
	}
	while (isalpha(*s)) s++;
	if (!isspace(*s)) {
		return bitch("%s is not valid", what);
	}
	*s++ = '\0';
	return s;
}

static char *extract_alnum(char *s, char *what)
{
	if (!isalnum(*s++)) {
		return bitch("%s expected", what);
	}
	while (isalnum(*s)) s++;
	if (!isspace(*s)) {
		return bitch("%s is not valid", what);
	}
	*s++ = '\0';
	return s;
}

static char *extract_ip(char *s, char *what, unsigned *ipptr)
{
	unsigned octet = 0;
	unsigned ip = 0;
	if (!isdigit(*s)) {
		return bitch("%s expected", what);
	}
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		return bitch("%s is not valid", what);
	}
	s++;
	if (!isdigit(*s)) {
		return bitch("%s is not valid", what);
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		return bitch("%s is not valid", what);
	}
	s++;
	if (!isdigit(*s)) {
		return bitch("%s is not valid", what);
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		return bitch("%s is not valid", what);
	}
	s++;
	if (!isdigit(*s)) {
		return bitch("%s is not valid", what);
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
		return bitch("%s is not valid", what);
	}
	*s++ = '\0';
	return s;
}

static void store_record(char *name, void *rrptr)
{
	struct rr *rr = rrptr;
	struct rr **chain;

	rr->line = file_info->line;
	rr->file_name = file_info->name;
	rr->next = NULL;
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
		return bitch("garbage after valid SOA data");
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
		return bitch("garbage after valid CNAME data");
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
		return bitch("garbage after valid MX data");
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
		return bitch("garbage after valid NS data");
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
		return bitch("wrong flags in DNSKEY");
	}
	GETINT(proto);
	if (proto != 3) {
		return bitch("unrecognized protocol in DNSKEY");
	}
	GETINT(algorithm);
	if (algorithm != 8) {
		return bitch("unsupported algorithm #%d in DNSKEY", algorithm);
	}

	if (*s) {
		return bitch("garbage after valid DNSKEY data");
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
		return bitch("garbage after valid A data");
	}

	/* XXX */
	return rr;
}

int
read_zone_file(void)
{
	char buf[2048];
	char *next, *s;
	char *name = NULL, *class, *rdtype;
	long ttl;
	while (file_info) {
		while (fgets(buf, 2048, file_info->file)) {
			file_info->line++;
			if (empty_line_or_comment(buf))
				continue;

			s = buf;
			if (!isspace(*s)) {
				/* <domain-name>, $INCLUDE, $ORIGIN */
				if (*s == '$') {
					bitch("$STUFF parsing not implemented");
					continue;
				} else {
					/* <domain-name> */
					name = extract_name(&s, "record name");
					if (!name)
						continue;
				}
			}
			if (!name) {
				bitch("cannot assume previous name for it is not known");
				continue;
			}
			bitch("the name is %s", name);
			continue;
			/* XXX classes IN, CS, CH, HS */
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
				bitch("unsupported class %s", class);
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
				bitch("invalid or unsupported rdtype %s", rdtype);
			}
		}
		if (ferror(file_info->file))
			croak(1, "read error for %s", file_info->name);
		file_info = file_info->next;
	}
	return 0;
}

void
open_zone_file(char *fname)
{
	FILE *f = fopen(fname, "r");
	struct file_info *new_file_info;

	if (!f)
		croak(1, "open %s", fname);
	new_file_info = malloc(sizeof(*new_file_info) + strlen(fname) + 1);
	if (!new_file_info)
		croak(1, "malloc(file_info), %s", fname);
	new_file_info->next = file_info;
	new_file_info->file = f;
	new_file_info->line = 0;
	strcpy(new_file_info->name, fname);
	file_info = new_file_info;
}

void usage(char *err)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "    %s -h\n", thisprogname());
	fprintf(stderr, "    %s [options]\n", thisprogname());
	fprintf(stderr, "Usage parameters:\n");
	fprintf(stderr, "\t-h\t\tproduce usage text and quit\n");
	fprintf(stderr, "\t-f\t\tquit on first validation error\n");
	fprintf(stderr, "\t-q\t\tquiet - do not produce any output\n");
	fprintf(stderr, "\t-s\t\tprint validation summary/stats\n");
	fprintf(stderr, "\t-v\t\tbe extra verbose\n");
	fprintf(stderr, "\t-I path\tuse this path for $INCLUDE files\n");
	fprintf(stderr, "\t-z origin\tuse this origin as initial $ORIGIN\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int o;
	bzero(&G.opt, sizeof(G.opt));
	bzero(&G.stats, sizeof(G.stats));

	while ((o = getopt(argc, argv, "fhqsvI:z:")) != -1) {
		switch(o) {
		case 'h':
			usage(NULL);
			break;
		case 'f':
			G.opt.die_on_first_error = 1;
			break;
		case 'q':
			G.opt.no_output = 1;
			break;
		case 's':
			G.opt.summary = 1;
			break;
		case 'v':
			G.opt.verbose = 1;
			break;
		case 'I':
			G.opt.include_path = optarg;
			break;
		case 'z':
			if (strlen(optarg) && *(optarg+strlen(optarg)-1) == '.') {
				G.opt.current_origin = optarg;
			} else if (strlen(optarg)) {
				G.opt.current_origin = getmem(strlen(optarg)+2);
				strcpy(stpcpy(G.opt.current_origin, optarg), ".");
			} else {
				usage("origin must not be empty");
			}
			break;
		default:
			usage(NULL);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage(NULL);
	open_zone_file(argv[0]);
	read_zone_file();
	if (G.opt.summary) {
		printf("records found:     %d\n", G.stats.rr_count);
		printf("record sets found: %d\n", G.stats.rrset_count);
		printf("validation errors: %d\n", G.stats.error_count);
	}
	return G.exit_code;
}
