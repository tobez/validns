#ifndef _RR_H
#define _RR_H 1

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define T_A		1
#define T_NS	2
#define T_CNAME	5
#define T_SOA	6
#define T_MX	15
#define T_TXT	16
#define T_AAAA	28
#define T_SRV	33
#define T_NAPTR	35
#define T_RRSIG	46
#define T_NSEC	47
#define T_DNSKEY	48
#define T_NSEC3	50
#define T_NSEC3PARAM	51
#define T_MAX	51

typedef void* (*rr_parse_func)(char *, long, int, char *);
typedef char* (*rr_human_func)(void *);
typedef void* (*rr_wire_func)(void *);
struct rr_methods {
	rr_parse_func rr_parse;
	rr_human_func rr_human;
	rr_wire_func  rr_wire;
};
extern struct rr_methods rr_methods[T_MAX+1];
extern struct rr_methods unknown_methods;

extern void *records;
void *store_record(int rdtype, char *name, long ttl, void *rrptr);
int str2rdtype(char *rdtype);
char *rdtype2str(int type);

struct rr
{
	struct rr* next;
	int	ttl;
	int rdtype;

	int line;
	char *file_name;
};

struct rr_a
{
	struct rr rr;
	uint32_t address;
};
extern struct rr_methods a_methods;

struct rr_soa
{
	struct rr rr;
	int serial, refresh, retry, expire, minimum;
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
    int length;
    char *txt;
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
	int type_bitmap_len;
	char *type_bitmap;
};
extern struct rr_methods nsec_methods;

struct rr_nsec3
{
	struct rr rr;
	/* XXX */
};

struct rr_nsec3param
{
	struct rr rr;
	/* XXX */
};

struct rr_rrsig
{
	struct rr rr;
	uint16_t type_covered;
	int algorithm;
	int labels;
	int orig_ttl;
	int sig_expiration;
	int sig_inception;
	uint16_t key_tag;
	char *signer;
	int sig_len;
	char *signature;
};
extern struct rr_methods rrsig_methods;

struct rr_srv
{
	struct rr rr;
	/* XXX */
};

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
	int pubkey_len;
	char *pubkey;
	uint16_t key_tag; /* calculated */
};
extern struct rr_methods dnskey_methods;

#endif
