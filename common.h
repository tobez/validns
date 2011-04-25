/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#ifndef _COMMON_H_
#define _COMMON_H_ 1

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
		int names_count;
		int rr_count;
		int rrset_count;
		int error_count;
		int skipped_dup_rr_count;
		int soa_rr_count;
	} stats;
	struct command_line_options
	{
		int die_on_first_error;
		int no_output;
		int summary;
		int verbose;
		char *include_path;
		char *current_origin;
		uint32_t current_time;
	} opt;
	int exit_code;
	long default_ttl;
	int nsec3_present;
	int nsec3_opt_out_present;
};

extern struct globals G;

#endif
