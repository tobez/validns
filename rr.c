#include <Judy.h>

#include "common.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

void *records = NULL;

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
		fprintf(stderr, "-> %s:%d: %s IN %ld",
				file_info->name, file_info->line,
				name, ttl);
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

static void* unknown_parse(char *name, long ttl, char *s)
{
	return bitch("unsupported resource record type");
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
