#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>

#include "carp.h"

static const char *thisprogname(void);
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

void
carp(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	v(0, errno, 0, fmt, ap);
	va_end(ap);
}

void
carpx(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	v(0, -1, 0, fmt, ap);
	va_end(ap);
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

static const char *thisprogname(void)
{
#if defined(__FreeBSD__)
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
