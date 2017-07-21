/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#ifndef _TEXTPARSE_H_
#define _TEXTPARSE_H_

#include <sys/types.h>

struct binary_data {
    int length;
    char *data;
};

struct binary_data compose_binary_data(const char *fmt, int tmp, ...);
/*
 * Format:
 * 1 - byte
 * 2 - 16-bit, will convert to network byte order
 * 4 - 32-bit, will convert to network byte order
 * d - another binary structure, will incorporate its data
 * b - another binary structure, will incorporate its data,
 *     and prepend the length as a byte (fatal error on overflow)
 * B - another binary structure, will incorporate its data,
 *     and prepend the length as a 16-bit word in NBO,
 *     fatal error on overflow
 * s - a NULL-terminated string, will incorporate the string
 *     without the NULL byte, and prepend the string length as a byte
 *     (fatal error on overflow)
 * tmp : allocate temp storage if true, permanent if false
 *
 */

#define KEEP_CAPITALIZATION 32
#define DOLLAR_OK_IN_NAMES  64

int empty_line_or_comment(char *s);
char *skip_white_space(char *s);
char *extract_name(char **input, char *what, int options);
char *extract_label(char **input, char *what, void *is_temporary);
long long extract_integer(char **input, char *what, const char *extra_delimiters);
long extract_timevalue(char **input, char *what);
long long extract_timestamp(char **input, char *what);
int extract_ipv4(char **input, char *what, struct in_addr *addr);
int extract_ipv6(char **input, char *what, struct in6_addr *addr);
int extract_u64(char **input, char *what, uint64_t *r);
int extract_double(char **input, char *what, double *val, int skip_m);
struct binary_data extract_base32hex_binary_data(char **input, char *what);
struct binary_data extract_base64_binary_data(char **input, char *what);
struct binary_data extract_text(char **input, char *what);

#define EXTRACT_DONT_EAT_WHITESPACE 0
#define EXTRACT_EAT_WHITESPACE 1
struct binary_data extract_hex_binary_data(char **input, char *what, int eat_whitespace);
struct binary_data bad_binary_data(void);

/* for NSEC/NSEC3 sets */
struct binary_data new_set(void);
void add_bit_to_set(struct binary_data *set, int bit);
struct binary_data compressed_set(struct binary_data *set);

char *mystpcpy(char *to, const char *from); /* stpcpy(3) is not available everywhere */
size_t mystrlcat(char *dst, const char *src, size_t siz); /* so is strlcat */

char *read_zone_line(void);

#endif
