/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "carp.h"
#include "mempool.h"
#include "textparse.h"
#include "base64.h"
#include "base32hex.h"

int empty_line_or_comment(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    if (!*s) return 1;
    if (*s == ';')  return 1;
    return 0;
}

char *skip_white_space(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    if (*s == ';') {
        while (*s) s++;
    }
    if (*s == 0) {
        if (file_info->paren_mode) {
            if (read_zone_line()) {
                return skip_white_space(file_info->buf);
            } else {
                return bitch("unexpected end of file");
            }
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
    if (*s == ')') {
        if (file_info->paren_mode) {
            file_info->paren_mode = 0;
            s++;
            return skip_white_space(s);
        } else {
            return bitch("unexpected closing parenthesis");
        }
    }
    return s;
}

static char *extract_name_slow(char **input, char *what, int options)
{
    char buf[1024];
    char *t = buf;
    char *s = *input;
    int d, l, ol;

    while (1) {
        if (isalnum((unsigned char)*s) || *s == '_' || *s == '.' || *s == '-' || *s == '/' || ((options & DOLLAR_OK_IN_NAMES) && *s == '$')) {
            if (t-buf >= 1022)
                return bitch("name too long");
            *t++ = *s++;
        } else if (*s == '\\') {
            s++;
            if (isdigit((unsigned char)*s)) {
                d = *s - '0';
                s++;
                if (!isdigit((unsigned char)*s))
                    return bitch("bad escape sequence");
                d = d*10 + *s - '0';
                s++;
                if (!isdigit((unsigned char)*s))
                    return bitch("bad escape sequence");
                d = d*10 + *s - '0';
                s++;
                if (d > 255)
                    return bitch("bad escape sequence");
                if (d == '.')
                    return bitch("a dot within a label is not currently supported");
                *((unsigned char *)t) = (unsigned char)d;
                if (t-buf >= 1022)
                    return bitch("name too long");
                t++;
            } else if (*s == '.') {
                return bitch("a dot within a label is not currently supported");
            } else if (*s) {
                if (t-buf >= 1022)
                    return bitch("name too long");
                *t++ = *s++;
            } else {
                return bitch("backslash in the end of the line not parsable");
            }
        } else {
            break;
        }
    }
    if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
        return bitch("%s is not valid", what);
    }
    *t = '\0';

    l = strlen(buf);
    if (!l)
        return bitch("%s should not be empty", what);

    if (buf[l-1] != '.') {
        if (!file_info->current_origin) {
            return bitch("do not know origin to determine %s", what);
        }
        ol = strlen(file_info->current_origin);
        if (file_info->current_origin[0] == '.') {
            if (l + ol >= 1023)
                return bitch("name too long");
            strcat(buf, file_info->current_origin);
        } else {
            if (l + ol >= 1022)
                return bitch("name too long");
            strcat(buf, ".");
            strcat(buf, file_info->current_origin);
        }
    }

    t = strchr(buf, '*');
    if (t && (t != buf || t[1] != '.'))
        return bitch("%s: bad wildcard", what);
    if (buf[0] == '.' && buf[1] != '\0')
        return bitch("%s: name cannot start with a dot", what);
    if (strstr(buf, ".."))
        return bitch("%s: empty label in a name", what);

    *input = skip_white_space(s);
    if (!*input)
        return NULL;  /* bitching's done elsewhere */
    if (!(options & KEEP_CAPITALIZATION)) {
        t = buf;
        while (*t) {
            *t = tolower((unsigned char)*t);
            t++;
        }
    }

    t = quickstrdup(buf);
    return t;
}

char *extract_name(char **input, char *what, int options)
{
    char *s = *input;
    char *r = NULL;
    char *end = NULL;
    char c;
    int wildcard = 0;

    if (*s == '@') {
        s++;
        if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
            return bitch("literal @ in %s is not all by itself", what);
        }
        if (!file_info->current_origin) {
            return bitch("do not know origin to expand @ in %s", what);
        }
        r = quickstrdup(file_info->current_origin);
    } else {
        if (!(isalnum((unsigned char)*s) || *s == '_' || *s == '.' || *s == '/' || ((options & DOLLAR_OK_IN_NAMES) && *s == '$'))) {
            if (*s == '*') {
                wildcard = 1;
            } else {
                if (*s == '\\')
                    return extract_name_slow(input, what, options);
                return bitch("%s expected", what);
            }
        }
        s++;
        while (isalnum((unsigned char)*s) || *s == '.' || *s == '-' || *s == '_' || *s == '/' || ((options & DOLLAR_OK_IN_NAMES) && *s == '$'))
            s++;
        if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
            if (*s == '\\')
                return extract_name_slow(input, what, options);
            return bitch("%s is not valid", what);
        }
        if (!*s)    end = s;
        c = *s;
        *s = '\0';
        if (*(s-1) == '.') {
            r = quickstrdup(*input);
        } else {
            if (!file_info->current_origin) {
                return bitch("do not know origin to determine %s", what);
            }
            r = getmem(strlen(*input) + 1 + strlen(file_info->current_origin) + 1);
            if (file_info->current_origin[0] == '.') {
                strcpy(mystpcpy(r, *input), file_info->current_origin);
            } else {
                strcpy(mystpcpy(mystpcpy(r, *input), "."), file_info->current_origin);
            }
        }
        *s = c;
    }
    if (end) {
        *input = end;
    } else {
        *input = skip_white_space(s);
        if (!*input)
            return NULL;  /* bitching's done elsewhere */
    }
    if (!(options & KEEP_CAPITALIZATION)) {
        s = r;
        while (*s) {
            *s = tolower((unsigned char)*s);
            s++;
        }
    }
    if (wildcard && r[1] != '.') {
        return bitch("%s: bad wildcard", what);
    } else if (r[0] == '.' && r[1] != '\0') {
        return bitch("%s: name cannot start with a dot", what);
    }
    return r;
}

char *extract_label(char **input, char *what, void *is_temporary)
{
    char *s = *input;
    char *r = NULL;
    char *end = NULL;

    if (!isalpha((unsigned char)*s)) {
        return bitch("%s expected", what);
    }
    s++;
    while (isalnum((unsigned char)*s))
        s++;
    if (*s && !isspace((unsigned char)*s)) {
        return bitch("%s is not valid", what);
    }
    if (!*s)    end = s;
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
        *s = tolower((unsigned char)*s);
        s++;
    }
    return r;
}

long long extract_integer(char **input, char *what, const char *extra_delimiters)
{
    char *s = *input;
    long long r = -1;
    char *end = NULL;
    char c;

    if (!isdigit((unsigned char)*s)) {
        bitch("%s expected", what);
        return -1;
    }
    s++;
    while (isdigit((unsigned char)*s))
        s++;
    if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
        if (!extra_delimiters || strchr(extra_delimiters, *s) == NULL) {
            bitch("%s is not valid", what);
            return -1;
        }
    }
    if (!*s)    end = s;
    c = *s;
    *s = '\0';
    r = strtoll(*input, NULL, 10);
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

int extract_double(char **input, char *what, double *val, int skip_m)
{
    char *s = *input;
    char *end = NULL;
    char *stop;
    char c;
    int saw_m = 0;

    while (isdigit((unsigned char)*s) || *s == '+' || *s == '-' || *s == '.')
        s++;
    if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
        if (skip_m && (*s == 'm' || *s == 'M')) {
            saw_m = 1;
        } else {
            bitch("%s is not valid", what);
            return -1;
        }
    }
    if (!*s)    end = s;
    c = *s;
    *s = '\0';
    *val = strtod(*input, &stop);
    if (*stop != '\0') {
        *s = c;
        bitch("%s is not valid", what);
        return -1;
    }
    *s = c;

    if (saw_m) {
        s++;
        if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
            bitch("%s is not valid", what);
            return -1;
        }
    }

    if (end) {
        *input = end;
    } else {
        *input = skip_white_space(s);
        if (!*input)
            return -1;  /* bitching's done elsewhere */
    }
    return 1;
}

long extract_timevalue(char **input, char *what)
{
    char *s = *input;
    int r = 0, acc = 0;

    if (!isdigit((unsigned char)*s)) {
        bitch("%s expected", what);
        return -1;
    }
next_component:
    r = 0;
    while (isdigit((unsigned char)*s)) {
        r *= 10;
        r += *s - '0';
        s++;
    }
    if (tolower((unsigned char)*s) == 's') {
        s++;
    } else if (tolower((unsigned char)*s) == 'm') {
        r *= 60;
        s++;
    } else if (tolower((unsigned char)*s) == 'h') {
        r *= 3600;
        s++;
    } else if (tolower((unsigned char)*s) == 'd') {
        r *= 86400;
        s++;
    } else if (tolower((unsigned char)*s) == 'w') {
        r *= 604800;
        s++;
    }
    acc += r;
    if (isdigit((unsigned char)*s)) goto next_component;

    if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
        bitch("%s is not valid", what);
        return -1;
    }
    *input = skip_white_space(s);
    if (!*input)
        return -1;  /* bitching's done elsewhere */
    return acc;
}

long long extract_timestamp(char **input, char *what)
{
    char *s = *input;
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    long long epoch = 0;
    struct tm tm;

    if (!isdigit((unsigned char)*s)) {
        bitch("%s expected", what);
        return -1;
    }
    year = year*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    year = year*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    year = year*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    year = year*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    month = month*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    month = month*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    day = day*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    day = day*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    hour = hour*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    hour = hour*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    minute = minute*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    minute = minute*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    second = second*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (!isdigit((unsigned char)*s)) goto looks_like_epoch;
    second = second*10 + *s - '0';
    epoch = epoch*10 + *s - '0';
    s++;
    if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
        bitch("%s is not valid", what);
        return -1;
    }
    if (second > 60 || minute > 59 || hour > 23 || day < 1 || day > 31 ||
        month > 12 || year < 1900 || year > 2037)
    {
        bitch("%s is not valid", what);
        return -1;
    }
    memset(&tm, 0, sizeof(tm));
    tm.tm_sec = second;
    tm.tm_min = minute;
    tm.tm_hour = hour;
    tm.tm_mday = day;
    tm.tm_mon = month - 1;
    tm.tm_year = year - 1900;
    epoch = mktime(&tm);
    if (epoch < 0) {
        bitch("%s is not valid", what);
        return -1;
    }

    goto done;

looks_like_epoch:
    if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
        bitch("%s is not valid", what);
        return -1;
    }
done:
    *input = skip_white_space(s);
    if (!*input)
        return -1;  /* bitching's done elsewhere */
    return epoch;
}

int extract_ipv4(char **input, char *what, struct in_addr *addr)
{
    char *s = *input;
    char c;

    while (isdigit((unsigned char)*s) || *s == '.') {
        s++;
    }
    if (s == *input) {
        bitch("%s is not valid", what);
        return -1;
    }
    if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
        bitch("%s is not valid", what);
        return -1;
    }
    c = *s;
    *s = 0;
    if (inet_pton(AF_INET, *input, addr) != 1) {
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

int extract_ipv6(char **input, char *what, struct in6_addr *addr)
{
    char *s = *input;
    char c;

    while (isdigit((unsigned char)*s) || *s == ':' || *s == '.' ||
          (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F'))
    {
        s++;
    }
    if (s == *input) {
        bitch("%s is not valid", what);
        return -1;
    }
    if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
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

int extract_u64(char **input, char *what, uint64_t *r)
{
    char *s = *input;
    uint8_t result = 0;
    unsigned u;

    #define GETHEXBLOCK if (!isxdigit((unsigned char)*s)) { bitch("%s is not valid", what); return -1; } \
        u = 0; \
        while (isxdigit((unsigned char)*s)) { \
            if (isdigit((unsigned char)*s)) { \
                u = (u << 4) | (*s - '0'); \
            } else if (*s >= 'a' && *s <= 'f') { \
                u = (u << 4) | (*s - 'a' + 10); \
            } else { \
                u = (u << 4) | (*s - 'A' + 10); \
            } \
            s++; \
        } \
        if (u > 0xffff) { bitch("%s is not valid, hex out of range", what); return -1; } \
        result = (result << 16) | u;
    #define SKIPCOLON if (*s != ':') { bitch("%s is not valid", what); return -1; } s++;

    GETHEXBLOCK; SKIPCOLON;
    GETHEXBLOCK; SKIPCOLON;
    GETHEXBLOCK; SKIPCOLON;
    GETHEXBLOCK;
    *r = result;

    #undef GETHEXBLOCK
    #undef SKIPCOLON

    if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
        bitch("%s is not valid", what);
        return -1;
    }
    *input = skip_white_space(s);
    if (!*input) {
        return -1;  /* bitching's done elsewhere */
    }
    return 1;
}

struct binary_data bad_binary_data(void)
{
    struct binary_data r;
    r.length = -1;
    r.data = NULL;
    return r;
}

void
dump_binary_data(FILE *f, struct binary_data d)
{
    char *s = d.data;
    int mem_len = d.length;
    int i;
    char o[69];
    int pos[] = { 0,3,6,9,12,15,18,21,25,28,31,34,37,40,43,46 };
    char hex[] = "0123456789abcdef";

    if (mem_len < 0) {
        fprintf(f, "<BAD DATA>\n");
        return;
    }

    while (mem_len) {
        memset(o, ' ', 67);
        o[67] = '\n';
        o[68] = 0;
        for (i = 0; i < 16 && mem_len > 0; i++, mem_len--, s++) {
            o[pos[i]] = hex[*s >> 4];
            o[pos[i]+1] = hex[*s & 0x0f];
            o[51+i] = isprint((unsigned char)*s) ? *s : '.';
        }
        fprintf(f, "%s", o);
    }
}

struct binary_data extract_base64_binary_data(char **input, char *what)
{
    char b64[4096];
    int l64 = 0;
    char *s = *input;
    struct binary_data r = bad_binary_data();
    int bl;

    while (s && *s) {
        if (!isalnum((unsigned char)*s) && *s != '=' && *s != '+' && *s != '/') {
            bitch("%s expected", what);
            return r;
        }
        while (isalnum((unsigned char)*s) || *s == '=' || *s == '+' || *s == '/') {
            if (l64 >= 4095) {
                bitch("%s is too long", what);
                return r;
            }
            b64[l64++] = *s++;
        }
        s = skip_white_space(s);
    }
    *input = s;
    if (!s) return r;
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

struct binary_data extract_base32hex_binary_data(char **input, char *what)
{
    char b32[4096];
    int l32 = 0;
    char *s = *input;
    struct binary_data r = bad_binary_data();
    int bl;

    while (
           (*s >= 'A' && *s <= 'V') ||
           (*s >= 'a' && *s <= 'v') ||
           (*s >= '0' && *s <= '9') ||
           *s == '=')
    {
        if (l32 >= 4095) {
            bitch("%s is too long", what);
            return r;
        }
        b32[l32++] = *s++;
    }
    if (l32 <= 0) {
        bitch("%s expected", what);
        return r;
    }

    s = skip_white_space(s);
    *input = s;
    if (!s) return r;

    b32[l32] = 0;
    bl = (l32 * 5 + 7)/8;
    r.data = getmem(bl);
    r.length = decode_base32hex(r.data, b32, bl);
    if (r.length < 0) {
        bitch("error decoding base32hex %s", what);
        return r;
    }
    return r;
}

struct binary_data extract_text(char **input, char *what)
{
    char *s = *input;
    struct binary_data r = bad_binary_data();
    char *o = getmem_temp(65536);
    int l = 0;
    int c;

    if (*s != '"') {
        while (*s && !isspace((unsigned char)*s)) {
            o[l++] = *s++;
        }
        *input = skip_white_space(s);
        if (!*input)
            return r;  /* bitching's done elsewhere */

        o[l] = 0;
        r.data = getmem(l+1);
        r.length = l;
        memcpy(r.data, o, l+1);
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
            } else if (isdigit((unsigned char)*s)) {
                c = 0;
                while (isdigit((unsigned char)*s)) {
                    c = c*10 + *s - '0';
                    s++;
                }
                o[l++] = (unsigned char)c;
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
        if (read_zone_line()) {
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

struct binary_data extract_hex_binary_data(char **input, char *what, int eat_whitespace)
{
    char hex[4096];
    char *s = *input;
    struct binary_data r = bad_binary_data();
    int hl, hi, hb;

    hex[0] = '0';
    hl = 1;

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    if (eat_whitespace == EXTRACT_DONT_EAT_WHITESPACE) {
        while (isxdigit((unsigned char)*s)) {
            if (hl >= 4095) {
                bitch("%s is too long", what);
                return r;
            }
            hex[hl] = *s;
            s++;
            hl++;
        }
        if (*s && !isspace((unsigned char)*s) && *s != ';' && *s != ')') {
            bitch("%s is not valid", what);
            return r;
        }
        *input = skip_white_space(s);
    } else if (eat_whitespace == EXTRACT_EAT_WHITESPACE) {
        while (s && *s) {
            if (!isxdigit((unsigned char)*s)) {
                bitch("%s expected", what);
                return r;
            }
            while (isxdigit((unsigned char)*s)) {
                if (hl >= 4095) {
                    bitch("%s is too long", what);
                    return r;
                }
                hex[hl++] = *s++;
            }
            s = skip_white_space(s);
        }
        *input = s;
    } else {
        bitch("%s: internal: invalid eat_whitespace", what);
    }

    if (!*input)
        return r;  /* bitching's done elsewhere */

    hb = hl % 2 ? 1 : 0;
    if (hb == 0)
        bitch("%s: hex data does not represent whole number of bytes", what);
    r.data = getmem(hl/2);
    r.length = hl/2;
    memset(r.data, 0, r.length);
    for (hi = 0; hi < hl-hb; hi++) {
        r.data[hi/2] <<= 4;
        r.data[hi/2] |= 0x0f & (isdigit((unsigned char)hex[hi+hb]) ? hex[hi+hb] - '0' : tolower((unsigned char)hex[hi+hb]) - 'a' + 10);
    }
    return r;
}

struct binary_data new_set(void)
{
    struct binary_data set;
    set.length = 256*(1+1+32);
    set.data = getmem_temp(set.length);
    memset(set.data, 0, set.length);
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

struct binary_data compose_binary_data(const char *fmt, int tmp, ...)
{
    va_list ap;
    const char *args;
    int sz;
    struct binary_data bd;
    struct binary_data r;
    char *t;
    uint8_t b1;
    uint16_t b2;
    uint32_t b4;
    uint64_t b8;
    char *bs;
    int bsl;

    va_start(ap, tmp);
    args = fmt;
    sz = 0;
    while (*args) {
        switch (*args++) {
        case '1':
            va_arg(ap, unsigned int);
            sz += 1;
            break;
        case '2':
            va_arg(ap, unsigned int);
            sz += 2;
            break;
        case '4':
            va_arg(ap, unsigned int);
            sz += 4;
            break;
        case '8':
            va_arg(ap, uint64_t);
            sz += 8;
            break;
        case 'd':
            bd = va_arg(ap, struct binary_data);
            sz += bd.length;
            break;
        case 'b':
            bd = va_arg(ap, struct binary_data);
            if (bd.length > 255)
                croak(5, "compose_binary_data: 'b' data too long");
            sz += bd.length + 1;
            break;
        case 'B':
            bd = va_arg(ap, struct binary_data);
            if (bd.length > 65535)
                croak(5, "compose_binary_data: 'B' data too long");
            sz += bd.length + 2;
            break;
        case 's':
            bs = va_arg(ap, char *);
            bsl = strlen(bs);
            if (bsl > 255)
                croak(5, "compose_binary_data: 's' string too long");
            sz += bsl + 1;
            break;
        default:
            croak(5, "compose_binary_data: bad format");
        }
    }
    va_end(ap);

    r.length = sz;
    r.data = tmp ? getmem_temp(sz) : getmem(sz);
    t = r.data;
    va_start(ap, tmp);
    args = fmt;
    while (*args) {
        switch (*args++) {
        case '1':
            b1 = (uint8_t)va_arg(ap, unsigned int);
            memcpy(t, &b1, 1);
            t += 1;
            break;
        case '2':
            b2 = htons(va_arg(ap, unsigned int));
            memcpy(t, &b2, 2);
            t += 2;
            break;
        case '4':
            b4 = htonl(va_arg(ap, unsigned int));
            memcpy(t, &b4, 4);
            t += 4;
            break;
        case '8':
            b8 = htonl(va_arg(ap, uint64_t));
            memcpy(t, &b8, 8);
            t += 8;
            break;
        case 'd':
            bd = va_arg(ap, struct binary_data);
            memcpy(t, bd.data, bd.length);
            t += bd.length;
            break;
        case 'b':
            bd = va_arg(ap, struct binary_data);
            b1 = (uint8_t)bd.length;
            memcpy(t, &b1, 1);
            t += 1;
            memcpy(t, bd.data, bd.length);
            t += bd.length;
            break;
        case 'B':
            bd = va_arg(ap, struct binary_data);
            b2 = htons(bd.length);
            memcpy(t, &b2, 2);
            t += 2;
            memcpy(t, bd.data, bd.length);
            t += bd.length;
            break;
        case 's':
            bs = va_arg(ap, char *);
            bsl = strlen(bs);
            b1 = (uint8_t)bsl;
            memcpy(t, &b1, 1);
            t += 1;
            memcpy(t, bs, bsl);
            t += bsl;
            break;
        default:
            croak(5, "compose_binary_data: bad format");
        }
    }
    va_end(ap);
    return r;
}

/* implementation taken from FreeBSD's libc (minus the __restrict keyword) */
char *
mystpcpy(char *to, const char *from)
{
    for (; (*to = *from); ++from, ++to);
    return(to);
}

size_t
mystrlcat(char *dst, const char *src, size_t siz)
{
    char *d = dst;
    const char *s = src;
    size_t n = siz;
    size_t dlen;

    /* Find the end of dst and adjust bytes left but don't go past end */
    while (n-- != 0 && *d != '\0')
        d++;
    dlen = d - dst;
    n = siz - dlen;

    if (n == 0)
        return(dlen + strlen(s));
    while (*s != '\0') {
        if (n != 1) {
            *d++ = *s;
            n--;
        }
        s++;
    }
    *d = '\0';

    return(dlen + (s - src));       /* count does not include NUL */
}

