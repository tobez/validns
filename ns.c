#include "common.h"
#include "rr.h"

static void *ns_parse(char *name, long ttl, char *s)
{
	struct rr_ns *rr = getmem(sizeof(*rr));

	rr->nsdname = extract_name(&s, "nsdname");
	if (!rr->nsdname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid NS data");
	}

	return store_record(T_NS, name, ttl, rr);
}

static char* ns_human(void *rrv)
{
    struct rr_ns *rr = rrv;
    char s[1024];

    snprintf(s, 1024, "NS %s", rr->nsdname);
    return quickstrdup_temp(s);
}

static void* ns_wirerdata(void *rrv)
{
    struct rr_ns *rr = rrv;

    return NULL;
}

struct rr_methods ns_methods = { ns_parse, ns_human, ns_wirerdata };
