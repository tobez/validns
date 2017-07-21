/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>

#include "common.h"
#include "carp.h"

static void v(int is_croak, int is_x, int exit_code, const char *fmt, va_list ap);

void
croak(int exit_code, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    v(1, errno, exit_code, fmt, ap);
    va_end(ap);
}

void
croakx(int exit_code, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    v(1, -1, exit_code, fmt, ap);
    va_end(ap);
}

void *
bitch(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (!G.opt.no_output) {
        fprintf(stderr, "%s:%d: ", file_info->name, file_info->line);
        if (fmt != NULL) {
            vfprintf(stderr, fmt, ap);
        }
        fprintf(stderr, "\n");
    }
    va_end(ap);
    G.exit_code = 1;
    G.stats.error_count++;
    file_info->paren_mode = 0;
    if (G.opt.die_on_first_error)
        exit(1);
    return NULL;
}

void *
moan(char *file_name, int line, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (!G.opt.no_output) {
        fprintf(stderr, "%s:%d: ", file_name, line);
        if (fmt != NULL) {
            vfprintf(stderr, fmt, ap);
        }
        fprintf(stderr, "\n");
    }
    va_end(ap);
    G.exit_code = 1;
    G.stats.error_count++;
    if (G.opt.die_on_first_error)
        exit(1);
    return NULL;
}

void
v(int is_croak, int use_errno, int exit_code, const char *fmt, va_list ap)
{
    fprintf(stderr, "%s: ", thisprogname());
    if (fmt != NULL) {
        vfprintf(stderr, fmt, ap);
        if (use_errno >= 0)
            fprintf(stderr, ": ");
    }
    if (use_errno >= 0)
        fprintf(stderr, "%s\n", strerror(use_errno));
    else
        fprintf(stderr, "\n");
    if (is_croak)
        exit(exit_code);
}

#if defined(__linux__)
static char proggy[MAXPATHLEN];
#endif

const char *thisprogname(void)
{
#if defined(__FreeBSD__)
    return getprogname();
#elif defined(__APPLE__)
    return getprogname();
#elif defined(__sun__)
    return getexecname();
#elif defined(__linux__)
    if (readlink("/proc/self/exe", proggy, MAXPATHLEN) != -1)
        return proggy;
    return "";
#else
#error "unsupported OS"
#endif
}
