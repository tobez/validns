/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#ifndef _BASE32HEX_H_
#define _BASE32HEX_H_ 1

int
decode_base32hex(void *dst, char *src, size_t dstsize);

#endif
