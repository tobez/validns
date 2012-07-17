/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, 2012 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#ifndef _CARP_H
#define _CARP_H 1

const char *thisprogname(void);

void croak(int exit_code, const char *fmt, ...);
void croakx(int exit_code, const char *fmt, ...);

void *bitch(const char *fmt, ...);
void *moan(char *file_name, int line, const char *fmt, ...);

#endif
