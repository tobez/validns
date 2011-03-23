#ifndef _RR_H
#define _RR_H 1

#include <unistd.h>

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
#define T_DNSKEY	48
#define T_NSEC3	50
#define T_NSEC3PARAM	51
#define T_MAX	51

typedef void* (*rr_parse_func)(char *, long, char *);
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
extern void *store_record(int rdtype, char *name, long ttl, void *rrptr);

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

struct rr_txt
{
	struct rr rr;
	/* XXX */
};

struct rr_naptr
{
	struct rr rr;
	/* XXX */
};

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
	/* XXX */
};

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

struct rr_aaaa
{
	struct rr rr;
	/* XXX */
};

struct rr_mx
{
	struct rr rr;
	int   preference;
	char *exchange;
};

struct rr_dnskey
{
	struct rr rr;
	/* XXX */
};

#endif
