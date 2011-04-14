/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#ifndef _TEXTPARSE_H_
#define _TEXTPARSE_H_

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
 * tmp : allocate temp storage if true, permanent if false
 *
 */

int empty_line_or_comment(char *s);
char *skip_white_space(char *s);
char *extract_name(char **input, char *what);
char *extract_label(char **input, char *what, void *is_temporary);
long long extract_integer(char **input, char *what);
long extract_timevalue(char **input, char *what);
long long extract_timestamp(char **input, char *what);
int extract_ipv4(char **input, char *what, struct in_addr *addr);
int extract_ipv6(char **input, char *what, struct in6_addr *addr);
struct binary_data extract_base64_binary_data(char **input, char *what);
struct binary_data extract_text(char **input, char *what);
struct binary_data extract_hex_binary_data(char **input, char *what);
struct binary_data bad_binary_data(void);

/* for NSEC/NSEC3 sets */
struct binary_data new_set(void);
void add_bit_to_set(struct binary_data *set, int bit);
struct binary_data compressed_set(struct binary_data *set);

#endif
