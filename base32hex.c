/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#include "base32hex.h"

/* base32/normal alignment:
 *
 *    0     1      2      3     4      5      6     7
 * |12345|123 45|12345|1 2345|1234 5|12345|12 345|12345|
 * |12345 678|12 34567 8|1234 5678|1 23456 78|123 45678|
 *      0          1          2         3          4
 *
 * normal byte 0 is (base32[0] << 3) | (base32[1] >> 2)
 *    masks: F8; 07
 * normal byte 1 is ((base32[1]&0x03) << 6) | (base32[2] << 1) | (base32[3] >> 4)
 *    masks: C0; 3E; 01
 * normal byte 2 is ((base32[3]&0x0F) << 4) | (base32[4] >> 1)
 *    masks: F0; 0F
 * normal byte 3 is ((base32[4]&0x01) << 7) | (base32[5] << 2) | (base32[6] >> 3)
 *    masks: 80; 7C; 03
 * normal byte 4 is ((base32[6]&0x07) << 5) | base32[7]
 *    masks: E0; 1F
 */

int
decode_base32hex(void *dest, char *src, size_t dstsize)
{
	size_t processed = 0;
	int full_bytes = 0;
	unsigned char *dst = dest;

	while (*src) {
		int v;
		if (*src >= 'A' && *src <= 'V')
			v = *src - 'A' + 10;
		else if (*src >= 'a' && *src <= 'z')
			v = *src - 'a' + 10;
		else if (*src >= '0' && *src <= '9')
			v = *src - '0';
		else if (isspace(*src) || *src == '=') {
			src++;
			continue;
		} else {
			/* any junk chars means input is corrupted */
			errno = EINVAL;
			return -1;
		}
		src++;
		if (processed % 8 == 0) {
			if (dstsize <= 0) {
				errno = EINVAL;
				return -1;
			}
			dst[0] &= 0x07;
			dst[0] |= (v << 5) & 0xF8;
			processed++;
		} else if (processed % 8 == 1) {
			if (dstsize < 1) {
				errno = EINVAL;
				return -1;
			}
			dst[0] &= 0xF8;
			dst[0] |= (v >> 4) & 0x03;
			if (dstsize >= 2) {
				dst[1] &= 0x0F;
				dst[1] |= (v << 4) & 0xF0;
			}
			processed++;
			full_bytes++;
		} else if (processed % 4 == 2) {
			if (dstsize < 2) {
				errno = EINVAL;
				return -1;
			}
			dst[1] &= 0xF0;
			dst[1] |= (v >> 2) & 0x0F;
			if (dstsize >= 3) {
				dst[2] &= 0x3F;
				dst[2] |= (v << 6) & 0xC0;
			}
			processed++;
			full_bytes++;
		} else {
			if (dstsize <= 2) {
				errno = EINVAL;
				return -1;
			}
			dst[2] &= 0xC0;
			dst[2] |= v & 0x3F;
			processed++;
			dst += 3;
			dstsize -= 3;
			full_bytes++;
		}
	}
	return full_bytes;
}

#ifdef TEST_PROGRAM

static int ok_string_test(int testnum, char *src, char *expect)
{
	unsigned char dstbuf[512];
	int r, r0, i;
	int expect_sz = strlen(expect);

	if (expect_sz >= 512) {
		printf("test %d: NOT OK: internal *test* error, buffer too small for proper testing, FIXME\n", testnum);
		return 1;
	}
	memset(dstbuf, 0xAA, 512);
	r = decode_base64(dstbuf, src, expect_sz);
	if (r != expect_sz) {
		printf("test %d: NOT OK: expect size %d, got %d\n", testnum, expect_sz, r);
		return 1;
	} else if (memcmp(dstbuf, expect, r) != 0) {
		printf("test %d: NOT OK: unexpected buffer content\n", testnum);
		return 1;
	}
	if (dstbuf[expect_sz] != 0xAA) {
		printf("test %d: NOT OK: corrupts memory with \"just enough\" bufsize\n", testnum);
		return 1;
	}
	memset(dstbuf, 0xAA, 512);
	for (i = 0; i < expect_sz; i++) {
		r0 = decode_base64(dstbuf, src, i);
		if (r0 > 0) {
			printf("test %d: NOT OK: buffer size %d should not be enough\n", testnum, i);
			return 1;
		}
		if (dstbuf[i] != 0xAA) {
			printf("test %d: NOT OK: corrupts memory with bufsize %d\n", testnum, i);
			return 1;
		}
	}
	printf("test %d: ok\n", testnum);
	return 0;
}

static int expect_junk_error(int testnum, char *src)
{
	char *buf[20];
	int r;

	r = decode_base64(buf, src, 20);
	if (r != -1) {
		printf("test %d: NOT OK: junk input not recognized\n", testnum);
		return 1;
	}
	printf("test %d: ok\n", testnum);
	return 0;
}

int main(void)
{
	int ret = 0;

	/* from http://en.wikipedia.org/wiki/Base64 */
	ret |= ok_string_test(1, "bGVhc3VyZS4=", "leasure.");
	ret |= ok_string_test(2, "bGVhc3VyZS4", "leasure.");
	ret |= ok_string_test(3, "ZWFzdXJlLg==", "easure.");
	ret |= ok_string_test(4, "ZWFzdXJlLg=", "easure.");
	ret |= ok_string_test(5, "ZWFzdXJlLg", "easure.");
	ret |= ok_string_test(6, "YXN1cmUu", "asure.");
	ret |= ok_string_test(7, "c3VyZS4=", "sure.");
	ret |= ok_string_test(8, "c3VyZS4", "sure.");
	ret |= ok_string_test(9, "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz\n"
		"IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg\n"
		"dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu\n"
		"dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo\n"
		"ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=",
		"Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.");
	/* from http://tools.ietf.org/html/rfc4648#section-10 */
	ret |= ok_string_test(10, "", "");
	ret |= ok_string_test(11, "Zg==", "f");
	ret |= ok_string_test(12, "Zg=", "f");
	ret |= ok_string_test(13, "Zg", "f");
	ret |= ok_string_test(14, "Zm8=", "fo");
	ret |= ok_string_test(15, "Zm8", "fo");
	ret |= ok_string_test(16, "Zm9v", "foo");
	ret |= ok_string_test(17, "Zm9vYg==", "foob");
	ret |= ok_string_test(18, "Zm9vYg=", "foob");
	ret |= ok_string_test(19, "Zm9vYg", "foob");
	ret |= ok_string_test(20, "Zm9vYmE=", "fooba");
	ret |= ok_string_test(21, "Zm9vYmE", "fooba");
	ret |= ok_string_test(22, "Zm9vYmFy", "foobar");

	ret |= expect_junk_error(23, "?Zm9vYmFy");
	ret |= expect_junk_error(24, "Z%m9vYmFy");
	ret |= expect_junk_error(25, "Zm&9vYmFy");
	ret |= expect_junk_error(26, "Zm9-vYmFy");
	ret |= expect_junk_error(27, "Zm9v*YmFy");
	ret |= expect_junk_error(28, "Zm9vY#mFy");
	ret |= expect_junk_error(29, "Zm9vYm\x01Fy");
	ret |= expect_junk_error(30, "Zm9vYmF!y");
	ret |= expect_junk_error(31, "Zm9vYmFy.");

	return ret;
}
#endif
