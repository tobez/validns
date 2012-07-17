/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, 2012 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#ifndef _MEMPOOL_H
#define _MEMPOOL_H 1

void mem_requirements_hint(size_t size);
void *getmem(size_t size);
char *quickstrdup(char *s);

int freeall_temp(void);
void *getmem_temp(size_t size);
char *quickstrdup_temp(char *s);

#endif
