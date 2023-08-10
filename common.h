/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#ifndef _COMMON_H_
#define _COMMON_H_ 1

struct generate_template_piece;
struct generate_template_piece
{
    char *constant_string;
    struct generate_template_piece *next;
};

#define LINEBUFSZ 2048

struct file_info
{
    struct file_info *next;
    FILE *file;
    int  line;
    int  paren_mode;
    char buf[LINEBUFSZ];
    char *current_origin;

    int generate_cur;
    int generate_lim;
    char *generate_type;
    struct generate_template_piece *generate_lhs;
    struct generate_template_piece *generate_rhs;

    /* must be last struct member */
    char name[0];
};

extern struct file_info *file_info;

#define N_POLICY_CHECKS 12
#define N_RESTRICTIVE_POLICY_CHECKS 11

#define POLICY_SINGLE_NS 0
#define POLICY_CNAME_OTHER_DATA 1
#define POLICY_NSEC3PARAM_NOT_APEX 2
#define POLICY_MX_ALIAS 3
#define POLICY_NS_ALIAS 4
#define POLICY_RP_TXT_EXISTS 5
#define POLICY_DNAME 6
#define POLICY_DNSKEY 7
#define POLICY_TLSA_HOST 8
#define POLICY_KSK_EXISTS 9
#define POLICY_SMIMEA_HOST 10
#define POLICY_PERMIT_STARTING_HYPHEN 11

#define MAX_TIMES_TO_CHECK 32

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
        int include_path_specified;
        char *first_origin;
        int n_times_to_check;
        uint32_t times_to_check[MAX_TIMES_TO_CHECK];
        char policy_checks[N_POLICY_CHECKS];
        int n_threads;
        int soa_minttl_as_default_ttl;
    } opt;
    int exit_code;
    long default_ttl;
    int nsec3_present;
    int nsec3_opt_out_present;
    int dnssec_active;
};

extern struct globals G;

#define SHA1_BYTES 20
#define SHA256_BYTES 32
#define SHA384_BYTES 48
#define SHA512_BYTES 64
/* GOST R 34.11-94 - 32 bytes */
#define GOST_BYTES 32

#endif
