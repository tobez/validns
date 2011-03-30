/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>

#include "common.h"
#include "base64.h"

int empty_line_or_comment(char *s)
{
	while (isspace(*s)) s++;
	if (!*s) return 1;
	if (*s == ';')	return 1;
	return 0;
}

char *skip_white_space(char *s)
{
	while (isspace(*s)) s++;
	if (*s == ';') {
		while (*s) s++;
	}
	if (*s == ')') {
		if (file_info->paren_mode) {
			file_info->paren_mode = 0;
			s++;
			return skip_white_space(s);
		} else {
			return bitch("unexpected closing parenthesis");
		}
	}
	if (*s == '(') {
		if (file_info->paren_mode) {
			return bitch("unexpected opening parenthesis");
		} else {
			file_info->paren_mode = 1;
			s++;
			return skip_white_space(s);
		}
	}
	if (*s == 0) {
		if (file_info->paren_mode) {
			if (fgets(file_info->buf, 2048, file_info->file)) {
				file_info->line++;
				return skip_white_space(file_info->buf);
			} else {
				return bitch("unexpected end of file");
			}
		}
	}
	return s;
}

char *extract_name(char **input, char *what)
{
	char *s = *input;
	char *r = NULL;
	char *end = NULL;

	if (*s == '@') {
		s++;
		if (*s && !isspace(*s)) {
			return bitch("literal @ in %s is not all by itself", what);
		}
		if (!G.opt.current_origin) {
			return bitch("do not know origin to expand @ in %s", what);
		}
		r = quickstrdup(G.opt.current_origin);
	} else {
		if (!(isalnum(*s) || *s == '_')) {
			return bitch("%s expected", what);
		}
		s++;
		while (isalnum(*s) || *s == '.' || *s == '-' || *s == '_')
			s++;
		if (*s && !isspace(*s)) {
			return bitch("%s is not valid", what);
		}
		if (!*s)	end = s;
		*s++ = '\0';
		if (*(s-2) == '.') {
			r = quickstrdup(*input);
		} else {
			if (!G.opt.current_origin) {
				return bitch("do not know origin to determine %s", what);
			}
			r = getmem(strlen(*input) + 1 + strlen(G.opt.current_origin) + 1);
			strcpy(stpcpy(stpcpy(r, *input), "."), G.opt.current_origin);
		}
	}
	if (end) {
		*input = end;
	} else {
		*input = skip_white_space(s);
		if (!*input)
			return NULL;  /* bitching's done elsewhere */
	}
	s = r;
	while (*s) {
		*s = tolower(*s);
		s++;
	}
	return r;
}

char *extract_label(char **input, char *what, void *is_temporary)
{
	char *s = *input;
	char *r = NULL;
	char *end = NULL;

	if (!isalpha(*s)) {
		return bitch("%s expected", what);
	}
	s++;
	while (isalnum(*s))
		s++;
	if (*s && !isspace(*s)) {
		return bitch("%s is not valid", what);
	}
	if (!*s)	end = s;
	*s++ = '\0';
	if (is_temporary) {
		r = quickstrdup_temp(*input);
	} else {
		r = quickstrdup(*input);
	}

	if (end) {
		*input = end;
	} else {
		*input = skip_white_space(s);
		if (!*input)
			return NULL;  /* bitching's done elsewhere */
	}
	s = r;
	while (*s) {
		*s = tolower(*s);
		s++;
	}
	return r;
}

long extract_integer(char **input, char *what)
{
	char *s = *input;
	int r = -1;
	char *end = NULL;
	char c;

	if (!isdigit(*s)) {
		bitch("%s expected", what);
		return -1;
	}
	s++;
	while (isdigit(*s))
		s++;
	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		bitch("%s is not valid", what);
		return -1;
	}
	if (!*s)	end = s;
	c = *s;
	*s = '\0';
	r = strtol(*input, NULL, 10);
	*s = c;

	if (end) {
		*input = end;
	} else {
		*input = skip_white_space(s);
		if (!*input)
			return -1;  /* bitching's done elsewhere */
	}
	return r;
}

long extract_timevalue(char **input, char *what)
{
	char *s = *input;
	int r = 0;

	if (!isdigit(*s)) {
		bitch("%s expected", what);
		return -1;
	}
	while (isdigit(*s)) {
		r *= 10;
		r += *s - '0';
		s++;
	}
	if (tolower(*s) == 's') {
		s++;
	} else if (tolower(*s) == 'm') {
		r *= 60;
		s++;
	} else if (tolower(*s) == 'h') {
		r *= 3600;
		s++;
	} else if (tolower(*s) == 'd') {
		r *= 86400;
		s++;
	} else if (tolower(*s) == 'w') {
		r *= 604800;
		s++;
	}

	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		bitch("%s is not valid", what);
		return -1;
	}
	*input = skip_white_space(s);
	if (!*input)
		return -1;  /* bitching's done elsewhere */
	return r;
}

long extract_timestamp(char **input, char *what)
{
	char *s = *input;
	int year = 0;
	int month = 0;
	int day = 0;
	int hour = 0;
	int minute = 0;
	int second = 0;
	int epoch = 0;
	struct tm tm;

	if (!isdigit(*s)) {
		bitch("%s expected", what);
		return -1;
	}
	year = year*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	year = year*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	year = year*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	year = year*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	month = month*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	month = month*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	day = day*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	day = day*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	hour = hour*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	hour = hour*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	minute = minute*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	minute = minute*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	second = second*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (!isdigit(*s)) goto looks_like_epoch;
	second = second*10 + *s - '0';
	epoch = epoch*10 + *s - '0';
	s++;
	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		bitch("%s is not valid", what);
		return -1;
	}
	if (second > 60 || minute > 59 || hour > 23 || day < 1 || day > 31 ||
		month > 12 || year < 1900 || year > 2037)
	{
		bitch("%s is not valid", what);
		return -1;
	}
	bzero(&tm, sizeof(tm));
	tm.tm_sec = second;
	tm.tm_min = minute;
	tm.tm_hour = hour;
	tm.tm_mday = day;
	tm.tm_mon = month - 1;
	tm.tm_year = year - 1900;
	epoch = timegm(&tm);
	if (epoch < 0) {
		bitch("%s is not valid", what);
		return -1;
	}

	goto done;

looks_like_epoch:
	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		bitch("%s is not valid", what);
		return -1;
	}
done:
	*input = skip_white_space(s);
	if (!*input)
		return -1;  /* bitching's done elsewhere */
	return epoch;
}

uint32_t extract_ip(char **input, char *what)
{
	char *s = *input;
	unsigned octet = 0;
	unsigned ip = 0;

	if (!isdigit(*s)) {
		bitch("%s expected", what);
		return 0;
	}
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		bitch("%s is not valid", what);
		return 0;
	}
	s++;
	if (!isdigit(*s)) {
		bitch("%s is not valid", what);
		return 0;
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		bitch("%s is not valid", what);
		return 0;
	}
	s++;
	if (!isdigit(*s)) {
		bitch("%s is not valid", what);
		return 0;
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	if (octet > 255 || *s != '.') {
		bitch("%s is not valid", what);
		return 0;
	}
	s++;
	if (!isdigit(*s)) {
		bitch("%s is not valid", what);
		return 0;
	}
	ip = 256*ip + octet;
	octet = 0;
	while (isdigit(*s)) {
		octet = 10*octet + *s - '0';
		s++;
	}
	ip = 256*ip + octet;

	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		bitch("%s is not valid", what);
		return 0;
	}

	*input = skip_white_space(s);
	if (!*input) {
		return 0;  /* bitching's done elsewhere */
	}

	return ip;
}

int extract_ipv6(char **input, char *what, struct in6_addr *addr)
{
	char *s = *input;
	char c;

	while (isdigit(*s) || *s == ':' || *s == '.' ||
		  (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F'))
	{
		s++;
	}
	if (s == *input) {
		bitch("%s is not valid", what);
		return -1;
	}
	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		bitch("%s is not valid", what);
		return -1;
	}
	c = *s;
	*s = 0;
	if (inet_pton(AF_INET6, *input, addr) != 1) {
		*s = c;
		bitch("cannot parse %s", what);
		return -1;
	}
	*s = c;
	*input = skip_white_space(s);
	if (!*input) {
		return -1;  /* bitching's done elsewhere */
	}
	return 1;
}

struct binary_data extract_base64_binary_data(char **input, char *what)
{
	char b64[4096];
	int l64 = 0;
	char *s = *input;
	struct binary_data r;
	int bl;

	r.length = -1;
	r.data = NULL;

	while (s && *s) {
		if (!isalnum(*s) && *s != '=' && *s != '+' && *s != '/') {
			bitch("%s expected", what);
			return r;
		}
		while (isalnum(*s) || *s == '=' || *s == '+' || *s == '/') {
			if (l64 >= 4095) {
				bitch("%s is too long", what);
				return r;
			}
			b64[l64++] = *s++;
		}
		s = skip_white_space(s);
	}
	*input = s;
	if (!s)	return r;
	b64[l64] = 0;
	bl = (l64 * 3 + 3)/4;
	r.data = getmem(bl);
	r.length = decode_base64(r.data, b64, bl);
	if (r.length < 0) {
		bitch("error decoding base64 %s", what);
		return r;
	}
	return r;
}

struct binary_data extract_text(char **input, char *what)
{
	char *s = *input;
	struct binary_data r;
	char *o = getmem_temp(65536);
	int l = 0;
	int c;

	r.length = -1;
	r.data = NULL;
	if (*s != '"') {
		bitch("for now, %s must be put in double quotes", what);
		return r;
	}
	s++;
more_text:
	while (*s && *s != '"') {
		if (*s == '\\') {
			s++;
			if (*s == 0) {
				bitch("bad backslash quoting of %s", what);
				return r;
			} else if (isdigit(*s)) {
				c = 0;
				while (isdigit(*s)) {
					c = c*10 + *s - '0';
					s++;
				}
				o[l] = (unsigned char)c;
			} else {
				o[l] = *s;
				goto new_char;
			}
		} else {
			o[l] = *s;
new_char:
			if (l >= 65534) {
				bitch("%s string too long", what);
				return r;
			}
			l++;
			s++;
		}
	}
	if (!*s) {
		if (fgets(file_info->buf, 2048, file_info->file)) {
			file_info->line++;
			s = file_info->buf;
			goto more_text;
		} else {
			bitch("closing quote not found while parsing %s", what);
			return r;
		}
	}
	s++;
	*input = skip_white_space(s);
	if (!*input)
		return r;  /* bitching's done elsewhere */

	o[l] = 0;
	r.data = getmem(l+1);
	r.length = l;
	memcpy(r.data, o, l+1);
	return r;
}

struct binary_data extract_hex_binary_data(char **input, char *what)
{
	char hex[4096];
	char *s = *input;
	struct binary_data r;
	int hl, hi, hb;

	r.length = -1;
	r.data = NULL;

	hex[0] = '0';
	hl = 1;
	while (isxdigit(*s)) {
		if (hl >= 4095) {
			bitch("%s is too long", what);
			return r;
		}
		hex[hl] = *s;
		s++;
		hl++;
	}

	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		bitch("%s is not valid", what);
		return r;
	}
	*input = skip_white_space(s);
	if (!*input)
		return r;  /* bitching's done elsewhere */

	r.data = getmem(hl/2);
	r.length = hl/2;
	bzero(r.data, r.length);
	hb = hl % 2 ? 1 : 0;
	for (hi = 0; hi < hl-hb; hi++) {
		r.data[hi/2] <<= 4;
		r.data[hi/2] |= 0x0f & (isdigit(hex[hi+hb]) ? hex[hi+hb] - '0' : tolower(hex[hi+hb]) - 'a' + 10);
	}
	return r;
}

struct binary_data new_set(void)
{
	struct binary_data set;
	set.length = 256*(1+1+32);
	set.data = getmem_temp(set.length);
	bzero(set.data, set.length);
	return set;
}

void add_bit_to_set(struct binary_data *set, int bit)
{
	int map;
	int map_base;
	int byte;

	if (bit < 0 || bit > 65535)
		croakx(1, "bitmap index out of range");
	map = bit / 256;
	map_base = map*(1+1+32);
	set->data[map_base] = map;
	bit = bit & 0xff;
	byte = bit / 8;
	if (set->data[map_base + 1] <= byte)
		set->data[map_base + 1] = byte+1;
	set->data[map_base + 2 + byte] |= 0x80 >> (bit & 0x07);
}

struct binary_data compressed_set(struct binary_data *set)
{
	int len = 0;
	int map;
	int map_base;
	struct binary_data r;

	for (map = 0; map <= 255; map++) {
		map_base = map*(1+1+32);
		if (set->data[map_base+1]) {
			len += 2 + set->data[map_base+1];
		}
	}
	r.length = len;
	r.data = getmem(r.length);
	len = 0;
	for (map = 0; map <= 255; map++) {
		map_base = map*(1+1+32);
		if (set->data[map_base+1]) {
			memcpy(&r.data[len], &set->data[map_base], 2 + set->data[map_base+1]);
			len += 2 + set->data[map_base+1];
		}
	}
	return r;
}

