/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static uint8_t double2loc_format(double val)
{
	if (val > 1000000000) {
		return (((uint8_t)(val / 1000000000)) << 4) | 9;
	} else if (val > 100000000) {
		return (((uint8_t)(val / 100000000)) << 4) | 8;
	} else if (val > 10000000) {
		return (((uint8_t)(val / 10000000)) << 4) | 7;
	} else if (val > 1000000) {
		return (((uint8_t)(val / 1000000)) << 4) | 6;
	} else if (val > 100000) {
		return (((uint8_t)(val / 100000)) << 4) | 5;
	} else if (val > 10000) {
		return (((uint8_t)(val / 10000)) << 4) | 4;
	} else if (val > 1000) {
		return (((uint8_t)(val / 1000)) << 4) | 3;
	} else if (val > 100) {
		return (((uint8_t)(val / 100)) << 4) | 2;
	} else if (val > 10) {
		return (((uint8_t)(val / 10)) << 4) | 1;
	} else {
		return (((uint8_t)(val)) << 4);
	}

}

static struct rr *loc_parse(char *name, long ttl, int type, char *s)
{
	struct rr_loc *rr = getmem(sizeof(*rr));
	long long i;
	int deg;
	int min;
	double sec, val;

	rr->version = 0;

	/* latitude block */
	i = extract_integer(&s, "degrees latitude");
	if (i < 0)
		return NULL;
	if (i > 90)
		return bitch("degrees latitude not in the range 0..90");
	deg = i;
	min = 0;
	sec = 0;
	if (isdigit(*s)) {
		i = extract_integer(&s, "minutes latitude");
		if (i < 0)
			return NULL;
		if (i > 59)
			return bitch("minutes latitude not in the range 0..59");
		min = i;

		if (isdigit(*s)) { /* restricted floating point, starting with a digit */
			if (extract_double(&s, "seconds latitude", &sec, 0) < 0)
				return NULL;
			if (sec < 0 || sec > 59.999)
				return bitch("seconds latitude not in the range 0..59.999");
		}
	}
	rr->latitude = sec*1000 + .5 + min*1000*60 + deg*1000*60*60;
	if (*s == 'n' || *s == 'N') {
		s++;
		rr->latitude = 2147483648u + rr->latitude;
	} else if (*s == 's' || *s == 'S') {
		s++;
		rr->latitude = 2147483648u - rr->latitude;
	} else {
		return bitch("latitude: N or S is expected");
	}
	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		return bitch("latitude: N or S is expected");
	}
	s = skip_white_space(s);
	if (!s) return NULL;

	/* longitude block */
	i = extract_integer(&s, "degrees longitude");
	if (i < 0)
		return NULL;
	if (i > 180)
		return bitch("degrees longitude not in the range 0..90");
	deg = i;
	min = 0;
	sec = 0;
	if (isdigit(*s)) {
		i = extract_integer(&s, "minutes longitude");
		if (i < 0)
			return NULL;
		if (i > 59)
			return bitch("minutes longitude not in the range 0..59");
		min = i;

		if (isdigit(*s)) { /* restricted floating point, starting with a digit */
			if (extract_double(&s, "seconds longitude", &sec, 0) < 0)
				return NULL;
			if (sec < 0 || sec > 59.999)
				return bitch("seconds longitude not in the range 0..59.999");
		}
	}
	rr->longitude = sec*1000 + .5 + min*1000*60 + deg*1000*60*60;
	if (*s == 'e' || *s == 'E') {
		s++;
		rr->longitude = 2147483648u + rr->longitude;
	} else if (*s == 'w' || *s == 'W') {
		s++;
		rr->longitude = 2147483648u - rr->latitude;
	} else {
		return bitch("longitude: E or W is expected");
	}
	if (*s && !isspace(*s) && *s != ';' && *s != ')') {
		return bitch("longitude: E or W is expected");
	}
	s = skip_white_space(s);
	if (!s) return NULL;

	if (extract_double(&s, "altitude", &val, 1) < 0)
		return NULL;
	if (val < -100000.00 || val > 42849672.95)
		return bitch("altitude is out of supported range");
	rr->altitude = (val + 100000.00) * 100 + 0.5;

	if (*s) {
		if (extract_double(&s, "sphere size", &val, 1) < 0)
			return NULL;
		if (val < 0 || val > 90000000.00)
			return bitch("sphere size is out of supported range");
		rr->size = double2loc_format(val * 100 + 0.5);

		if (*s) {
			if (extract_double(&s, "horizontal precision", &val, 1) < 0)
				return NULL;
			if (val < 0 || val > 90000000.00)
				return bitch("horizontal precision is out of supported range");
			rr->horiz_pre = double2loc_format(val * 100 + 0.5);

			if (*s) {
				if (extract_double(&s, "vertical precision", &val, 1) < 0)
					return NULL;
				if (val < 0 || val > 90000000.00)
					return bitch("vertical precision is out of supported range");
				rr->vert_pre = double2loc_format(val * 100 + 0.5);
			} else {
				rr->vert_pre = double2loc_format(10 * 100 + 0.5);
			}
		} else {
			rr->horiz_pre = double2loc_format(10000 * 100 + 0.5);
		}
	} else {
		rr->size = double2loc_format(1 * 100 + 0.5);
	}

	if (*s) {
		return bitch("garbage after valid LOC data");
	}

	return store_record(type, name, ttl, rr);
}

static char* loc_human(struct rr *rrv)
{
    // struct rr_loc *rr = (struct rr_loc *)rrv;
    // char s[1024];

    // snprintf(s, 1024, "\"%s\" \"%s\"", rr->cpu.data, rr->os.data);
    // return quickstrdup_temp(s);
	return "meow";
}

static struct binary_data loc_wirerdata(struct rr *rrv)
{
    struct rr_loc *rr = (struct rr_loc *)rrv;

    return compose_binary_data("1111444", 1,
		rr->version, rr->size,
		rr->horiz_pre, rr->vert_pre,
		rr->latitude, rr->longitude, rr->altitude);
}

struct rr_methods loc_methods = { loc_parse, loc_human, loc_wirerdata, NULL, NULL };
