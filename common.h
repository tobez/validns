#ifndef _COMMON_H_
#define _COMMON_H_ 1

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "carp.h"
#include "mempool.h"
#include "textparse.h"

struct file_info
{
	struct file_info *next;
	FILE *file;
	int  line;
	int  paren_mode;
	char buf[2048];
	char name[0];
};

extern struct file_info *file_info;

struct globals {
	struct stats {
		int rr_count;
		int rrset_count;
		int error_count;
	} stats;
	struct command_line_options
	{
		int die_on_first_error;
		int no_output;
		int summary;
		int verbose;
		char *include_path;
		char *current_origin;
	} opt;
	int exit_code;
	long default_ttl;
};

extern struct globals G;

#endif
