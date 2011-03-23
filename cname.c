#include "common.h"
#include "rr.h"

static void *cname_parse(char *name, long ttl, char *s)
{
	struct rr_cname *rr = getmem(sizeof(*rr));

	rr->cname = extract_name(&s, "cname");
	if (!rr->cname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid CNAME data");
	}

	return store_record(T_CNAME, name, ttl, rr);
}

static char* cname_human(void *rrv)
{
    struct rr_cname *rr = rrv;
    return rr->cname;
}

static void* cname_wirerdata(void *rrv)
{
    struct rr_cname *rr = rrv;

    return NULL;
}

struct rr_methods cname_methods = { cname_parse, cname_human, cname_wirerdata };
