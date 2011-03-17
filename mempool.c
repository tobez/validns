#include <stdlib.h>
#include <string.h>

#include "mempool.h"
#include "carp.h"

struct pool
{
	struct pool *next;
	size_t pool_size;
	size_t free_index;
	char mem[0];
};

static struct pool *freespace = NULL;

static void new_pool(size_t size)
{
	struct pool *pool;

	size = (size + sizeof(void *) - 1) / sizeof(void *);
	size *= sizeof(void *);
	pool = malloc(size + sizeof(struct pool));
	if (!pool)
		croak(1, "new_pool malloc");
	pool->next = freespace;
	pool->free_index = 0;
	pool->pool_size = size;
	freespace = pool;
}

void
mem_requirements_hint(size_t size)
{
	if (freespace) return;
	new_pool(size);
}

void *getmem(size_t size)
{
	void *ret;
	size = (size + sizeof(void *) - 1) / sizeof(void *);
	size *= sizeof(void *);
	if (!freespace)	new_pool(size > 256000 ? size : 256000);
	if (freespace->pool_size - freespace->free_index < size)
		new_pool(size > 256000 ? size : 256000);
	ret = freespace->mem + freespace->free_index;
	freespace->free_index += size;
	return ret;
}

char *quickstrdup(char *s)
{
	char *r = getmem(strlen(s)+1);
	return strcpy(r, s);
}
