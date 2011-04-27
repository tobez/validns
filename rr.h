/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#ifndef _RR_H
#define _RR_H 1

#define T_A		1
#define T_NS	2
#define T_CNAME	5
#define T_SOA	6
#define T_HINFO	13
#define T_MX	15
#define T_TXT	16
#define T_AAAA	28
#define T_LOC	29
#define T_SRV	33
#define T_NAPTR	35
#define T_DS	43
#define T_RRSIG	46
#define T_NSEC	47
#define T_DNSKEY	48
#define T_NSEC3	50
#define T_NSEC3PARAM	51
#define T_MAX	51

extern char *zone_name;
extern int zone_name_l;

struct named_rr;
struct rr_set;
struct rr;

typedef struct rr* (*rr_parse_func)(char *, long, int, char *);
typedef char* (*rr_human_func)(struct rr*);
typedef struct binary_data (*rr_wire_func)(struct rr*);
typedef void* (*rr_validate_set_func)(struct rr_set*);
typedef void* (*rr_validate_func)(struct rr*);
struct rr_methods {
	rr_parse_func        rr_parse;
	rr_human_func        rr_human;
	rr_wire_func         rr_wire;
	rr_validate_set_func rr_validate_set;
	rr_validate_func     rr_validate;
};
extern struct rr_methods rr_methods[T_MAX+1];
extern struct rr_methods unknown_methods;

void validate_record(struct rr *rr);
void validate_zone(void);
struct rr *store_record(int rdtype, char *name, long ttl, void *rrptr);
int str2rdtype(char *rdtype);
char *rdtype2str(int type);
struct named_rr *find_named_rr(char *name);
struct named_rr *find_next_named_rr(struct named_rr *named_rr);
struct rr_set *find_rr_set(int rdtype, char *name);
struct rr_set *find_rr_set_in_named_rr(struct named_rr *named_rr, int rdtype);
uint32_t get_rr_set_count(struct named_rr *named_rr);
struct binary_data name2wire_name(char *s);

struct named_rr
{
	char *name;
	void *rr_sets;

	int line;
	char *file_name;
};

struct rr_set
{
	struct rr* head;
	struct rr* tail;
	struct named_rr *named_rr;
	int rdtype;
	int count;
};

struct rr
{
	struct rr* next;
	struct rr* prev;
	struct rr_set *rr_set;

	int	ttl;
	int rdtype;

	int line;
	char *file_name;
};

struct rr_a
{
	struct rr rr;
	struct in_addr address;
};
extern struct rr_methods a_methods;

struct rr_soa
{
	struct rr rr;
	uint32_t serial;
	int refresh, retry, expire, minimum;
	char *rname;
	char *mname;
};
extern struct rr_methods soa_methods;

struct rr_ns
{
    struct rr rr;
    char *nsdname;
};
extern struct rr_methods ns_methods;

struct rr_txt
{
    struct rr rr;
    struct binary_data txt;
};
extern struct rr_methods txt_methods;

struct rr_naptr
{
    struct rr rr;
	uint16_t order;
	uint16_t preference;
	struct binary_data flags;
	struct binary_data services;
	struct binary_data regexp;
	char *replacement;
};
extern struct rr_methods naptr_methods;

struct rr_nsec
{
	struct rr rr;
	char *next_domain;
	struct binary_data type_bitmap;
};
extern struct rr_methods nsec_methods;

struct rr_nsec3
{
	struct rr rr;
	uint8_t hash_algorithm;
	uint8_t flags;
	uint16_t iterations;
	struct binary_data salt;
	struct binary_data next_hashed_owner;
	struct binary_data type_bitmap;
};
extern struct rr_methods nsec3_methods;

struct rr_nsec3param
{
	struct rr rr;
	uint8_t hash_algorithm;
	uint8_t flags;
	uint16_t iterations;
	struct binary_data salt;
};
extern struct rr_methods nsec3param_methods;

struct rr_rrsig
{
	struct rr rr;
	uint16_t type_covered;
	int algorithm;
	int labels;
	int orig_ttl;
	uint32_t sig_expiration;
	uint32_t sig_inception;
	uint16_t key_tag;
	char *signer;
	struct binary_data signature;
};
extern struct rr_methods rrsig_methods;

struct rr_srv
{
	struct rr rr;
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	char *target;
};
extern struct rr_methods srv_methods;

struct rr_cname
{
	struct rr rr;
	char *cname;
};
extern struct rr_methods cname_methods;

struct rr_aaaa
{
	struct rr rr;
	struct in6_addr address;
};
extern struct rr_methods aaaa_methods;

struct rr_mx
{
	struct rr rr;
	int   preference;
	char *exchange;
};
extern struct rr_methods mx_methods;

struct rr_dnskey
{
	struct rr rr;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;
	struct binary_data pubkey;
	/* calculated */
	uint16_t key_tag;
	int pkey_built;
	void *pkey;
};
extern struct rr_methods dnskey_methods;

int dnskey_build_pkey(struct rr_dnskey *rr);

struct rr_ds
{
	struct rr rr;
	uint16_t key_tag;
	uint8_t algorithm;
	uint8_t digest_type;
	struct binary_data digest;
};
extern struct rr_methods ds_methods;

struct rr_hinfo
{
	struct rr rr;
    struct binary_data cpu;
    struct binary_data os;
};
extern struct rr_methods hinfo_methods;

struct rr_loc
{
	struct rr rr;
	uint8_t version;
	uint8_t size;
	uint8_t horiz_pre;
	uint8_t vert_pre;
	uint32_t latitude;
	uint32_t longitude;
	uint32_t altitude;
};
extern struct rr_methods loc_methods;

#endif
