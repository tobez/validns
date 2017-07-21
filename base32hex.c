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
        else if (*src >= 'a' && *src <= 'v')
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
            dst[0] |= (v << 3) & 0xF8;
            processed++;
        } else if (processed % 8 == 1) {
            if (dstsize < 1) {
                errno = EINVAL;
                return -1;
            }
            dst[0] &= 0xF8;
            dst[0] |= (v >> 2) & 0x07;
            if (dstsize >= 2) {
                dst[1] &= 0x3F;
                dst[1] |= (v << 6) & 0xC0;
            }
            processed++;
            full_bytes++;
        } else if (processed % 8 == 2) {
            if (dstsize < 2) {
                errno = EINVAL;
                return -1;
            }
            dst[1] &= 0xC1;
            dst[1] |= (v << 1) & 0x3E;
            processed++;
        } else if (processed % 8 == 3) {
            if (dstsize < 2) {
                errno = EINVAL;
                return -1;
            }
            dst[1] &= 0xFE;
            dst[1] |= (v >> 4) & 0x01;
            if (dstsize >= 3) {
                dst[2] &= 0x0F;
                dst[2] |= (v << 4) & 0xF0;
            }
            processed++;
            full_bytes++;
        } else if (processed % 8 == 4) {
            if (dstsize < 3) {
                errno = EINVAL;
                return -1;
            }
            dst[2] &= 0xF0;
            dst[2] |= (v >> 1) & 0x0F;
            if (dstsize >= 4) {
                dst[3] &= 0x7F;
                dst[3] |= (v << 7) & 0x80;
            }
            processed++;
            full_bytes++;
        } else if (processed % 8 == 5) {
            if (dstsize < 4) {
                errno = EINVAL;
                return -1;
            }
            dst[3] &= 0x83;
            dst[3] |= (v << 2) & 0x7C;
            processed++;
        } else if (processed % 8 == 6) {
            if (dstsize < 4) {
                errno = EINVAL;
                return -1;
            }
            dst[3] &= 0xFC;
            dst[3] |= (v >> 3) & 0x03;
            if (dstsize >= 5) {
                dst[4] &= 0x1F;
                dst[4] |= (v << 5) & 0xE0;
            }
            processed++;
            full_bytes++;
        } else {
            if (dstsize < 5) {
                errno = EINVAL;
                return -1;
            }
            dst[4] &= 0xE0;
            dst[4] |= v & 0x1F;
            processed++;
            dst += 5;
            dstsize -= 5;
            full_bytes++;
        }
    }
    return full_bytes;
}

int
encode_base32hex(void *dest, size_t dstsize, void *source, size_t srclength)
{
    size_t need_dstsize;
    int byte = 0;
    unsigned char *dst = dest;
    unsigned char *src = source;
    int i;

    need_dstsize = 8*(srclength / 5);
    switch (srclength % 5) {
    case 1: need_dstsize += 2; break;
    case 2: need_dstsize += 4; break;
    case 3: need_dstsize += 5; break;
    case 4: need_dstsize += 7; break;
    }
    if (dstsize < need_dstsize) {
        errno = EINVAL;
        return -1;
    }
    while (srclength) {
        switch (byte) {
        case 0:
            dst[0] = *src >> 3;
            dst[1] = (*src & 0x07) << 2;
            break;
        case 1:
            dst[1] |= (*src >> 6) & 0x03;
            dst[2] = (*src >> 1) & 0x1f;
            dst[3] = (*src & 0x01) << 4;
            break;
        case 2:
            dst[3] |= (*src >> 4) & 0x0f;
            dst[4] = (*src & 0x0f) << 1;
            break;
        case 3:
            dst[4] |= (*src >> 7) & 0x01;
            dst[5] = (*src >> 2) & 0x1f;
            dst[6] = (*src & 0x03) << 3;
            break;
        case 4:
            dst[6] |= (*src >> 5) & 0x07;
            dst[7] = *src & 0x1f;
            break;
        }

        srclength--;
        src++;
        byte++;
        if (byte == 5) {
            dst += 8;
            byte = 0;
        }
    }
    dst = dest;
    for (i = 0; i < need_dstsize; i++) {
        if (*dst < 10)
            *dst = *dst +'0';
        else if (*dst < 32)
            *dst = *dst - 10 + 'a';
        else
            *dst = '?';
        dst++;
    }
    return need_dstsize;
}

#ifdef TEST_PROGRAM

static int ok_string_test(int testnum, char *src, char *expect)
{
    unsigned char dstbuf[512];
    unsigned char reverse_buf[1024];
    int r, r0, i;
    int expect_sz = strlen(expect);
    int expect_reverse;
    char *s, *d;

    if (expect_sz >= 512) {
        printf("test %d: NOT OK: internal *test* error, buffer too small for proper testing, FIXME\n", testnum);
        return 1;
    }
    memset(dstbuf, 0xAA, 512);
    r = decode_base32hex(dstbuf, src, expect_sz);
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
    r = encode_base32hex(reverse_buf, 1024, dstbuf, expect_sz);
    s = src;  d = (char*)dstbuf;
    expect_reverse = 0;
    while (*s) {
        if (*s != ' ' && *s != '=') {
            *d++ = tolower(*s);
            expect_reverse++;
        }
        s++;
    }
    if (r != expect_reverse) {
        printf("test %d: NOT OK: REVERSE: expect size %d, got %d\n", testnum, expect_reverse, r);
        return 1;
    } else if (memcmp(reverse_buf, dstbuf, r) != 0) {
        printf("test %d: NOT OK: REVERSE: unexpected buffer content\n", testnum);
        return 1;
    }
    memset(dstbuf, 0xAA, 512);
    for (i = 0; i < expect_sz; i++) {
        r0 = decode_base32hex(dstbuf, src, i);
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

    r = decode_base32hex(buf, src, 20);
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
    int t = 1;

    /* from http://tools.ietf.org/html/rfc4648#section-10 */
    ret |= ok_string_test(t++, "", "");
    ret |= ok_string_test(t++, "CO======", "f");
    ret |= ok_string_test(t++, "Co=====", "f");
    ret |= ok_string_test(t++, "cO====", "f");
    ret |= ok_string_test(t++, "co===", "f");
    ret |= ok_string_test(t++, "CO==", "f");
    ret |= ok_string_test(t++, "CO=", "f");
    ret |= ok_string_test(t++, "CO", "f");

    ret |= ok_string_test(t++, "CPNG====", "fo");
    ret |= ok_string_test(t++, "cPNG===", "fo");
    ret |= ok_string_test(t++, "cpNG==", "fo");
    ret |= ok_string_test(t++, "cpnG=", "fo");
    ret |= ok_string_test(t++, "cpng", "fo");

    ret |= ok_string_test(t++, "CPNMU===", "foo");
    ret |= ok_string_test(t++, "CPnMU==", "foo");
    ret |= ok_string_test(t++, "CPnmu=", "foo");
    ret |= ok_string_test(t++, "cpNMU", "foo");

    ret |= ok_string_test(t++, "CPNMUOG=", "foob");
    ret |= ok_string_test(t++, "CPNMUoG", "foob");

    ret |= ok_string_test(t++, "CPNMUOJ1", "fooba");
    ret |= ok_string_test(t++, "cPnMuOj1", "fooba");
    ret |= ok_string_test(t++, "CpNmUoJ1", "fooba");
    ret |= ok_string_test(t++, "CpNm   UoJ1", "fooba");

    ret |= ok_string_test(t++, "CPNMUOJ1E8======", "foobar");
    ret |= ok_string_test(t++, "CPNMuOJ1E8=====", "foobar");
    ret |= ok_string_test(t++, "CpNMuOJ1E8====", "foobar");
    ret |= ok_string_test(t++, "CpNMuOJ1e8===", "foobar");
    ret |= ok_string_test(t++, "CpNmuOJ 1e8==", "foobar");
    ret |= ok_string_test(t++, "CpnmuOJ 1e8=", "foobar");
    ret |= ok_string_test(t++, "Cpn muOj 1e8", "foobar");

    ret |= expect_junk_error(t++, "?m9vmF");
    ret |= expect_junk_error(t++, "%m9vmF");
    ret |= expect_junk_error(t++, "m&9vmF");
    ret |= expect_junk_error(t++, "m9-vmF");
    ret |= expect_junk_error(t++, "m9v*mF");
    ret |= expect_junk_error(t++, "m9v#mF");
    ret |= expect_junk_error(t++, "m9vm\x01F");
    ret |= expect_junk_error(t++, "m9vmF!");
    ret |= expect_junk_error(t++, "m9vmF.");
    ret |= expect_junk_error(t++, "CpnmuOj/1e8x");
    ret |= expect_junk_error(t++, "CpnYmuOj1e8");
    ret |= expect_junk_error(t++, "CZpnmuOj1e8");
    ret |= expect_junk_error(t++, "CzpnmuOj1e8");

    ret |= ok_string_test(t++, "MEQIMI6FJE5NI47PJAHV5QIGU1LV3JLJ", "\xb3\xb5\x2b\x48\xcf\x9b\x8b\x79\x10\xf9\x9a\xa3\xf2\xea\x50\xf0\x6b\xf1\xce\xb3");

    return ret;
}
#endif
