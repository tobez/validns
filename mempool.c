/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
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
static struct pool *temp_freespace = NULL;

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

void *getmem_temp(size_t size)
{
	void *ret;
	size = (size + sizeof(void *) - 1) / sizeof(void *);
	size *= sizeof(void *);
	if (!temp_freespace) {
		size_t pool_size = size > 1024*1024 ? size : 1024*1024;
		pool_size = (pool_size + sizeof(void *) - 1) / sizeof(void *);
		pool_size *= sizeof(void *);
		temp_freespace = malloc(pool_size + sizeof(struct pool));
		if (!temp_freespace)
			croak(1, "getmem_temp malloc");
		temp_freespace->next = NULL;
		temp_freespace->free_index = 0;
		temp_freespace->pool_size = pool_size;
	}
	if (temp_freespace->pool_size - temp_freespace->free_index < size)
		croak(1, "getmem_temp request too large");
	ret = temp_freespace->mem + temp_freespace->free_index;
	temp_freespace->free_index += size;
	return ret;
}

int freeall_temp(void)
{
	if (temp_freespace) {
		temp_freespace->free_index = 0;
	}
	return 1;
}

char *quickstrdup(char *s)
{
	char *r = getmem(strlen(s)+1);
	return strcpy(r, s);
}

char *quickstrdup_temp(char *s)
{
	char *r = getmem_temp(strlen(s)+1);
	return strcpy(r, s);
}
