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
	if (*s == ')') {
		if (file_info->paren_mode) {
			file_info->paren_mode = 0;
			s++;
			return skip_white_space(s);
		} else {
			return bitch("unexpected closing parenthesis");
		}
	}
	if (*s == '(') {
		if (file_info->paren_mode) {
			return bitch("unexpected opening parenthesis");
		} else {
			file_info->paren_mode = 1;
			s++;
			return skip_white_space(s);
		}
	}
	if (*s == 0) {
		if (file_info->paren_mode) {
			if (fgets(file_info->buf, 2048, file_info->file)) {
				file_info->line++;
				return skip_white_space(file_info->buf);
			} else {
				return bitch("unexpected end of file");
			}
		}
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
		if (!*input)
			return NULL;  /* bitching's done elsewhere */
	}
	s = r;
	while (*s) {
		*s = tolower(*s);
		s++;
	}
	return r;
}

static char *extract_label(char **input, char *what, void *is_temporary)
{
	char *s = *input;
	char *r = NULL;
	char *end = NULL;

	if (!isalpha(*s)) {
		return bitch("%s expected", what);
	}
	s++;
	while (isalnum(*s))
		s++;
	if (*s && !isspace(*s)) {
		return bitch("%s is not valid", what);
	}
	if (!*s)	end = s;
	*s++ = '\0';
	if (is_temporary) {
		r = quickstrdup_temp(*input);
	} else {
		r = quickstrdup(*input);
	}

	if (end) {
		*input = end;
	} else {
		*input = skip_white_space(s);
		if (!*input)
			return NULL;  /* bitching's done elsewhere */
	}
	s = r;
	while (*s) {
		*s = tolower(*s);
		s++;
	}
	return r;
}

static long extract_integer(char **input, char *what)
{
	char *s = *input;
	int r = -1;
	char *end = NULL;
	char c;

	if (!isdigit(*s)) {
		bitch("%s expected", what);
		return -1;
	}
	s++;
	while (isdigit(*s))
		s++;
	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		bitch("%s is not valid", what);
		return -1;
	}
	if (!*s)	end = s;
	c = *s;
	*s = '\0';
	r = strtol(*input, NULL, 10);
	*s = c;

	if (end) {
		*input = end;
	} else {
		*input = skip_white_space(s);
		if (!*input)
			return -1;  /* bitching's done elsewhere */
	}
	return r;
}

static long extract_timevalue(char **input, char *what)
{
	char *s = *input;
	int r = 0;
	int m;
	char *end = NULL;
	char c;

	if (!isdigit(*s)) {
		bitch("%s expected", what);
		return -1;
	}
	while (isdigit(*s)) {
		r *= 10;
		r += *s - '0';
		s++;
	}
	if (tolower(*s) == 's') {
		s++;
	} else if (tolower(*s) == 'm') {
		r *= 60;
		s++;
	} else if (tolower(*s) == 'h') {
		r *= 3600;
		s++;
	} else if (tolower(*s) == 'd') {
		r *= 86400;
		s++;
	} else if (tolower(*s) == 'w') {
		r *= 604800;
		s++;
	}

	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		bitch("%s is not valid", what);
		return -1;
	}
	*input = skip_white_space(s);
	if (!*input)
		return -1;  /* bitching's done elsewhere */
	return r;
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

static uint32_t extract_ip(char **input, char *what)
{
	char *s = *input;
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
		bitch("%s is not valid", what);
		return 0;
	}
	s++;
	if (!isdigit(*s)) {
		bitch("%s is not valid", what);
		return 0;
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		bitch("%s is not valid", what);
		return 0;
	}
	s++;
	if (!isdigit(*s)) {
		bitch("%s is not valid", what);
		return 0;
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		bitch("%s is not valid", what);
		return 0;
	}
	s++;
	if (!isdigit(*s)) {
		bitch("%s is not valid", what);
		return 0;
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	ip = 256*ip + octet;

	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		bitch("%s is not valid", what);
		return 0;
	}

	*input = skip_white_space(s);
	if (!*input) {
		return 0;  /* bitching's done elsewhere */
	}

	return ip;
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

static void* parse_soa(char *name, long ttl, char *s)
{
	char *mname, *rname;
	long serial, refresh, retry, expire, minimum;
	struct rr_soa *rr;

	mname = extract_name(&s, "mname");
	if (!mname) return NULL;
	rname = extract_name(&s, "rname");
	if (!rname) return NULL;
	serial = extract_integer(&s, "serial");
	if (serial < 0) return NULL;
	refresh = extract_timevalue(&s, "refresh");
	if (refresh < 0) return NULL;
	retry = extract_timevalue(&s, "retry");
	if (retry < 0) return NULL;
	expire = extract_timevalue(&s, "expire");
	if (expire < 0) return NULL;
	minimum = extract_timevalue(&s, "minimum");
	if (minimum < 0) return NULL;
	if (*s) {
		return bitch("garbage after valid SOA data");
	}

	if (G.opt.verbose) {
		fprintf(stderr, "-> %s:%d: ", file_info->name, file_info->line);
		fprintf(stderr, "parse_soa: %s IN %d SOA %s %s %d %d %d %d %d\n", name, ttl,
				mname, rname, serial, refresh, retry, expire, minimum);
	}

	rr = getmem(sizeof(*rr));
	rr->rr.ttl    = ttl;
	rr->rr.rdtype = T_SOA;
	rr->mname     = mname;
	rr->rname     = rname;
	rr->serial    = serial;
	rr->refresh   = refresh;
	rr->retry     = retry;
	rr->expire    = expire;
	rr->minimum   = minimum;

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

	// GETNAME(cname);
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
	long preference;
	char *exchange;
	struct rr_mx *rr;

	preference = extract_integer(&s, "MX preference");
	if (preference < 0)
		return NULL;
	/* XXX prefernce range check */
	exchange = extract_name(&s, "MX exchange");
	if (!exchange)
		return NULL;
	if (*s) {
		return bitch("garbage after valid MX data");
	}

	if (G.opt.verbose) {
		fprintf(stderr, "-> %s:%d: ", file_info->name, file_info->line);
		fprintf(stderr, "parse_mx: %s IN %d MX %d %s\n", name, ttl, preference, exchange);
	}

	rr = getmem(sizeof(*rr));
	rr->rr.ttl     = ttl;
	rr->rr.rdtype  = T_MX;
	rr->preference = preference;
	rr->exchange   = exchange;
	store_record(name, rr);
	return rr;
}

static void *parse_ns(char *name, long ttl, char *s)
{
	char *nsdname;
	struct rr_ns *rr;

	nsdname = extract_name(&s, "nsdname");
	if (!nsdname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid NS data");
	}

	if (G.opt.verbose) {
		fprintf(stderr, "-> %s:%d: ", file_info->name, file_info->line);
		fprintf(stderr, "parse_ns: %s IN %d NS %s\n", name, ttl, nsdname);
	}

	rr = getmem(sizeof(*rr));
	rr->rr.ttl    = ttl;
	rr->rr.rdtype = T_NS;
	rr->nsdname   = nsdname;
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

	// GETINT(flags);
	if (flags != 256 && flags != 257) {
		return bitch("wrong flags in DNSKEY");
	}
	// GETINT(proto);
	if (proto != 3) {
		return bitch("unrecognized protocol in DNSKEY");
	}
	// GETINT(algorithm);
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
	uint32_t address;
	struct rr_a *rr;

	address = extract_ip(&s, "nsdname");
	if (!address)
		return NULL;
	if (*s) {
		return bitch("garbage after valid A data");
	}

	if (G.opt.verbose) {
		fprintf(stderr, "-> %s:%d: ", file_info->name, file_info->line);
		fprintf(stderr, "parse_a: %s IN %d A %d.%d.%d.%d\n", name, ttl,
				0xff & (address >> 24), 0xff & (address >> 16),
				0xff & (address >> 8), 0xff & address);
	}

	rr = getmem(sizeof(*rr));
	rr->rr.ttl    = ttl;
	rr->rr.rdtype = T_A;
	rr->address   = address;
	store_record(name, rr);
	return rr;
}

static char *process_directive(char *s)
{
	if (*(s+1) == 'O' && strncmp(s, "$ORIGIN", 7) == 0) {
		char *o;
		s += 7;
		if (!isspace(*s)) {
			return bitch("bad $ORIGIN format");
		}
		s = skip_white_space(s);
		o = extract_name(&s, "$ORIGIN value");
		if (!o) {
			return NULL;
		}
		if (*s) {
			return bitch("garbage after valid $ORIGIN directive");
		}
		G.opt.current_origin = o;
		if (G.opt.verbose) {
			fprintf(stderr, "-> %s:%d: ", file_info->name, file_info->line);
			fprintf(stderr, "origin is now %s\n", o);
		}
	} else if (*(s+1) == 'T' && strncmp(s, "$TTL", 4) == 0) {
		s += 4;
		if (!isspace(*s)) {
			return bitch("bad $TTL format");
		}
		s = skip_white_space(s);
		G.default_ttl = extract_timevalue(&s, "$TTL value");
		if (G.default_ttl < 0) {
			return NULL;
		}
		if (*s) {
			return bitch("garbage after valid $TTL directive");
		}
		if (G.opt.verbose) {
			fprintf(stderr, "-> %s:%d: ", file_info->name, file_info->line);
			fprintf(stderr, "default ttl is now %d\n", G.default_ttl);
		}
	} else if (*(s+1) == 'I' && strncmp(s, "$INCLUDE", 8) == 0) {
		s += 8;
		if (!isspace(*s)) {
			return bitch("bad $INCLUDE format");
		}
		s = skip_white_space(s);
		return bitch("XXX include support is not implemented");
	} else {
		return bitch("unrecognized directive");
	}
	return s;
}

int
read_zone_file(void)
{
	char *next, *s;
	char *name = NULL, *class, *rdtype;
	long ttl = 0;
	while (file_info) {
		while (fgets(file_info->buf, 2048, file_info->file)) {
			freeall_temp();
			file_info->line++;
			file_info->paren_mode = 0;
			rdtype = NULL;
			if (empty_line_or_comment(file_info->buf))
				continue;

			s = file_info->buf;
			if (!isspace(*s)) {
				/* <domain-name>, $INCLUDE, $ORIGIN */
				if (*s == '$') {
					process_directive(s);
					continue;
				} else {
					/* <domain-name> */
					name = extract_name(&s, "record name");
					if (!name)
						continue;
				}
			} else {
				s = skip_white_space(s);
			}
			if (!name) {
				bitch("cannot assume previous name for it is not known");
				continue;
			}
			if (isdigit(*s)) {
				ttl = extract_timevalue(&s, "TTL");
				if (ttl < 0)
					continue;
				class = extract_label(&s, "class or type", "temporary");
				if (!class)
					continue;
				if (*class == 'i' && *(class+1) == 'n' && *(class+2) == 0) {
				} else if (*class == 'c' && *(class+1) == 's' && *(class+2) == 0) {
					bitch("CSNET class is not supported");
					continue;
				} else if (*class == 'c' && *(class+1) == 'h' && *(class+2) == 0) {
					bitch("CHAOS class is not supported");
					continue;
				} else if (*class == 'h' && *(class+1) == 's' && *(class+2) == 0) {
					bitch("HESIOD class is not supported");
					continue;
				} else {
					rdtype = class;
				}
			} else {
				class = extract_label(&s, "class or type", "temporary");
				if (!class)
					continue;
				if (*class == 'i' && *(class+1) == 'n' && *(class+2) == 0) {
					if (isdigit(*s)) {
						ttl = extract_timevalue(&s, "TTL");
						if (ttl < 0)
							continue;
					}
				} else if (*class == 'c' && *(class+1) == 's' && *(class+2) == 0) {
					bitch("CSNET class is not supported");
					continue;
				} else if (*class == 'c' && *(class+1) == 'h' && *(class+2) == 0) {
					bitch("CHAOS class is not supported");
					continue;
				} else if (*class == 'h' && *(class+1) == 's' && *(class+2) == 0) {
					bitch("HESIOD class is not supported");
					continue;
				} else {
					rdtype = class;
				}
			}
			if (!rdtype) {
				rdtype = extract_label(&s, "type", "temporary");
			}
			if (!rdtype) {
				continue;
			}
			if (ttl <= 0) {
				ttl = G.default_ttl;
			}
			if (ttl <= 0) {
				bitch("ttl not specified and default is not known");
				continue;
			}

			switch (*rdtype) {
			case 'a':
				if (strcmp(rdtype, "a") == 0) {
					parse_a(name, ttl, s);
					break;
				} else if (strcmp(rdtype, "aaaa") == 0) {
					parse_aaaa(name, ttl, s);
					break;
				}
			case 'c':
				if (strcmp(rdtype, "cname") == 0) {
					parse_cname(name, ttl, s);
					break;
				}
			case 'd':
				if (strcmp(rdtype, "dnskey") == 0) {
					parse_dnskey(name, ttl, s);
					break;
				}
			case 'm':
				if (strcmp(rdtype, "mx") == 0) {
					parse_mx(name, ttl, s);
					break;
				}
			case 'n':
				if (strcmp(rdtype, "ns") == 0) {
					parse_ns(name, ttl, s);
					break;
				} else if (strcmp(rdtype, "naptr") == 0) {
					parse_naptr(name, ttl, s);
					break;
				} else if (strcmp(rdtype, "nsec3") == 0) {
					parse_nsec3(name, ttl, s);
					break;
				} else if (strcmp(rdtype, "nsec3param") == 0) {
					parse_nsec3param(name, ttl, s);
					break;
				}
			case 'r':
				if (strcmp(rdtype, "rrsig") == 0) {
					parse_rrsig(name, ttl, s);
					break;
				}
			case 's':
				if (strcmp(rdtype, "soa") == 0) {
					parse_soa(name, ttl, s);
					break;
				} else if (strcmp(rdtype, "srv") == 0) {
					parse_srv(name, ttl, s);
					break;
				}
			case 't':
				if (strcmp(rdtype, "txt") == 0) {
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
	G.default_ttl = 3600; /* XXX orly? */

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
