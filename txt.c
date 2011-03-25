#include "common.h"
#include "rr.h"

static void *txt_parse(char *name, long ttl, int type, char *s)
{
	struct rr_txt *rr = getmem(sizeof(*rr));
	struct binary_data txt;

	txt = extract_text(&s, "text");
	if (txt.length < 0)
		return NULL;
	if (*s) {
		return bitch("garbage after valid TXT data");
	}
	rr->length = txt.length;
	rr->txt = txt.data;

	return store_record(type, name, ttl, rr);
}

static char* txt_human(void *rrv)
{
    struct rr_txt *rr = rrv;
    char s[1024];

    snprintf(s, 1024, "\"%s\"", rr->txt);
    return quickstrdup_temp(s);
}

static void* txt_wirerdata(void *rrv)
{
    struct rr_soa *rr = rrv;

    return NULL;
}

struct rr_methods txt_methods = { txt_parse, txt_human, txt_wirerdata };
