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

#define N_POLICY_CHECKS 8

#define POLICY_SINGLE_NS 0
#define POLICY_CNAME_OTHER_DATA 1
#define POLICY_NSEC3PARAM_NOT_APEX 2
#define POLICY_MX_ALIAS 3
#define POLICY_NS_ALIAS 4
#define POLICY_RP_TXT_EXISTS 5
#define POLICY_DNAME 6
#define POLICY_DNSKEY 7

struct globals {
	struct stats {
		int names_count;
		int rr_count;
		int rrset_count;
		int error_count;
		int skipped_dup_rr_count;
		int soa_rr_count;
		int signatures_verified;
		int delegations;
		int not_authoritative;
		int nsec3_count;
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
		char policy_checks[N_POLICY_CHECKS];
		int n_threads;
	} opt;
	int exit_code;
	long default_ttl;
	int nsec3_present;
	int nsec3_opt_out_present;
};

extern struct globals G;

#endif
