#include "common.h"
#include "rr.h"

static void *naptr_parse(char *name, long ttl, int type, char *s)
{
	struct rr_naptr *rr = getmem(sizeof(*rr));
	int i;
	struct binary_data text;

	i = extract_integer(&s, "order");
	if (i < 0)
		return NULL;
	if (i >= 65536)
		return bitch("order is not valid");
	rr->order = i;

	i = extract_integer(&s, "preference");
	if (i < 0)
		return NULL;
	if (i >= 65536)
		return bitch("preference is not valid");
	rr->preference = i;

	text = extract_text(&s, "flags");
	if (text.length < 0)
		return NULL;
	for (i = 0; i < text.length; i++) {
		if (!isalnum(text.data[i])) {
			return bitch("flags contains illegal characters");
		}
	}
	rr->flags = text;

	text = extract_text(&s, "services");
	if (text.length < 0)
		return NULL;
	rr->services = text;

	text = extract_text(&s, "regexp");
	if (text.length < 0)
		return NULL;
	rr->regexp = text;

	rr->replacement = extract_name(&s, "replacement");
	if (!rr->replacement)
		return NULL;

	if (*s) {
		return bitch("garbage after valid NAPTR data");
	}

	return store_record(type, name, ttl, rr);
}

static char* naptr_human(void *rrv)
{
    struct rr_naptr *rr = rrv;
    char s[1024];

	snprintf(s, 1024, "%hu %hu \"%s\" ...",
			 rr->order, rr->preference, rr->flags.data);

	return quickstrdup_temp(s);
}

static void* naptr_wirerdata(void *rrv)
{
    struct rr_soa *rr = rrv;

    return NULL;
}

struct rr_methods naptr_methods = { naptr_parse, naptr_human, naptr_wirerdata };
