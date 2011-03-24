#include "common.h"
#include "rr.h"

static void *a_parse(char *name, long ttl, int type, char *s)
{
	struct rr_a *rr = getmem(sizeof(*rr));

	rr->address = extract_ip(&s, "nsdname");
	if (!rr->address)
		return NULL;
	if (*s) {
		return bitch("garbage after valid A data");
	}

	return store_record(type, name, ttl, rr);
}

static char* a_human(void *rrv)
{
    struct rr_a *rr = rrv;
    char s[1024];

    snprintf(s, 1024, "%d.%d.%d.%d",
			 0xff & (rr->address >> 24), 0xff & (rr->address >> 16),
			 0xff & (rr->address >> 8), 0xff & rr->address);
    return quickstrdup_temp(s);
}

static void* a_wirerdata(void *rrv)
{
    struct rr_soa *rr = rrv;

    return NULL;
}

struct rr_methods a_methods = { a_parse, a_human, a_wirerdata };
