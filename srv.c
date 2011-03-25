#include "common.h"
#include "rr.h"

static void *srv_parse(char *name, long ttl, int type, char *s)
{
	struct rr_srv *rr = getmem(sizeof(*rr));
	int i;

	/* TODO validate `name` (underscores etc) http://tools.ietf.org/html/rfc2782 */

	i = extract_integer(&s, "priority");
	if (i < 0)
		return NULL;
	if (i >= 65536)
		return bitch("priority range is not valid");
	rr->priority = i;

	i = extract_integer(&s, "weight");
	if (i < 0)
		return NULL;
	if (i >= 65536)
		return bitch("weight range is not valid");
	rr->weight = i;

	i = extract_integer(&s, "port");
	if (i < 0)
		return NULL;
	if (i >= 65536)
		return bitch("port range is not valid");
	rr->port = i;

	rr->target = extract_name(&s, "target");
	if (!rr->target)
		return NULL;

	if (*s) {
		return bitch("garbage after valid SRV data");
	}

	return store_record(type, name, ttl, rr);
}

static char* srv_human(void *rrv)
{
    struct rr_srv *rr = rrv;
    char s[1024];

	snprintf(s, 1024, "%hu %hu %hu %s",
			 rr->priority, rr->weight, rr->port, rr->target);

	return quickstrdup_temp(s);
}

static void* srv_wirerdata(void *rrv)
{
    struct rr_soa *rr = rrv;

    return NULL;
}

struct rr_methods srv_methods = { srv_parse, srv_human, srv_wirerdata };
