/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

/* see http://tools.ietf.org/html/rfc4398 */
/*
static struct rr *ptr_parse(char *name, long ttl, int type, char *s)
{
	struct rr_ptr *rr = getmem(sizeof(*rr));

	rr->ptrdname = extract_name(&s, "name server domain name");
	if (!rr->ptrdname)
		return NULL;
	if (*s) {
		return bitch("garbage after valid PTR data");
	}

	return store_record(type, name, ttl, rr);
}

static char* ptr_human(struct rr *rrv)
{
	RRCAST(ptr);

    return rr->ptrdname;
}

static struct binary_data ptr_wirerdata(struct rr *rrv)
{
	RRCAST(ptr);
	return name2wire_name(rr->ptrdname);
}
*/

struct rr_methods cert_methods = { NULL, any_human, any_wirerdata, NULL, NULL };
