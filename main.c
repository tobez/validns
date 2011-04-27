/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "carp.h"
#include "mempool.h"
#include "textparse.h"
#include "rr.h"

struct globals G;
struct file_info *file_info = NULL;

int
read_zone_file(void);

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
			fprintf(stderr, "default ttl is now %ld\n", G.default_ttl);
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
	char *s;
	char *name = NULL, *class, *rdtype;
	long ttl = -1;
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
			if (!s)
				continue;
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
			if (ttl < 0) {
				ttl = G.default_ttl;
			}
			if (ttl < 0) {
				bitch("ttl not specified and default is not known");
				continue;
			}

			{
				int type = str2rdtype(rdtype);
				if (type <= 0 || type > T_MAX) continue;
				rr_methods[type].rr_parse(name, ttl, type, s);
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
	fprintf(stderr, "    %s [options] zone-file\n", thisprogname());
	fprintf(stderr, "Usage parameters:\n");
	fprintf(stderr, "\t-h\t\tproduce usage text and quit\n");
	fprintf(stderr, "\t-f\t\tquit on first validation error\n");
	fprintf(stderr, "\t-q\t\tquiet - do not produce any output\n");
	fprintf(stderr, "\t-s\t\tprint validation summary/stats\n");
	fprintf(stderr, "\t-v\t\tbe extra verbose\n");
	fprintf(stderr, "\t-I path\tuse this path for $INCLUDE files\n");
	fprintf(stderr, "\t-z origin\tuse this origin as initial $ORIGIN\n");
	fprintf(stderr, "\t-t epoch-time\tuse this time instead of \"now\"\n");
	exit(1);
}

struct rr_methods rr_methods[T_MAX+1];

static void initialize_globals(void)
{
	int i;

	bzero(&G, sizeof(G));
	bzero(&G.opt, sizeof(G.opt));
	bzero(&G.stats, sizeof(G.stats));
	G.default_ttl = 3600; /* XXX orly? */
	G.opt.current_time = time(NULL);

	for (i = 0; i <= T_MAX; i++) {
		rr_methods[i] = unknown_methods;
	}
	rr_methods[T_A]            =          a_methods;
	rr_methods[T_AAAA]         =       aaaa_methods;
	rr_methods[T_CNAME]        =      cname_methods;
	rr_methods[T_DNSKEY]       =     dnskey_methods;
	rr_methods[T_DS]           =         ds_methods;
	rr_methods[T_HINFO]        =      hinfo_methods;
	rr_methods[T_LOC]          =        loc_methods;
	rr_methods[T_MX]           =         mx_methods;
	rr_methods[T_NAPTR]        =      naptr_methods;
	rr_methods[T_NS]           =         ns_methods;
	rr_methods[T_NSEC]         =       nsec_methods;
	rr_methods[T_NSEC3]        =      nsec3_methods;
	rr_methods[T_NSEC3PARAM]   = nsec3param_methods;
	rr_methods[T_RRSIG]        =      rrsig_methods;
	rr_methods[T_SOA]          =        soa_methods;
	rr_methods[T_SRV]          =        srv_methods;
	rr_methods[T_TXT]          =        txt_methods;
}

int
main(int argc, char **argv)
{
	int o;
	initialize_globals();

	while ((o = getopt(argc, argv, "fhqsvI:z:t:")) != -1) {
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
		case 't':
			G.opt.current_time = strtol(optarg, NULL, 10);
			if (G.opt.verbose)
				fprintf(stderr, "using time %d instead of \"now\"\n", G.opt.current_time);
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
	validate_zone();
	if (G.opt.summary) {
		printf("records found:      %d\n", G.stats.rr_count);
		printf("skipped dups:       %d\n", G.stats.skipped_dup_rr_count);
		printf("record sets found:  %d\n", G.stats.rrset_count);
		printf("unique names found: %d\n", G.stats.names_count);
		printf("validation errors:  %d\n", G.stats.error_count);
	}
	return G.exit_code;
}
