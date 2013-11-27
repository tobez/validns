/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011, 2012 Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

struct verification_data
{
	struct verification_data *next;
	EVP_MD_CTX ctx;
	struct rr_dnskey *key;
	struct rr_rrsig *rr;
	int ok;
	unsigned long openssl_error;
};

struct keys_to_verify
{
	struct keys_to_verify *next;
	struct rr_rrsig *rr;
	struct rr_set *signed_set;
	int n_keys;
	struct verification_data to_verify[1];
};

static struct keys_to_verify *all_keys_to_verify = NULL;

static struct rr* rrsig_parse(char *name, long ttl, int type, char *s)
{
	struct rr_rrsig *rr = getmem(sizeof(*rr));
	int type_covered, key_tag;
	char *str_type_covered;
	struct binary_data sig;
	long long ts;

	str_type_covered = extract_label(&s, "type covered", "temporary");
	if (!str_type_covered) return NULL;
	type_covered = str2rdtype(str_type_covered, NULL);
	if (type_covered <= 0 || type_covered > 65535) return NULL;
	rr->type_covered = type_covered;

	rr->algorithm = extract_algorithm(&s, "algorithm");
	if (rr->algorithm == ALG_UNSUPPORTED)	return NULL;
	if (rr->algorithm == ALG_PRIVATEDNS || rr->algorithm == ALG_PRIVATEOID) {
		return bitch("private algorithms are not supported in RRSIG");
	}

	rr->labels = extract_integer(&s, "labels");
	if (rr->labels < 0)	return NULL;
	/* TODO validate labels, see http://tools.ietf.org/html/rfc4034#section-3.1.3 */

	rr->orig_ttl = extract_timevalue(&s, "original TTL");
	if (rr->orig_ttl < 0) return NULL;

	ts = extract_timestamp(&s, "signature expiration");
	if (ts < 0) return NULL;
	rr->sig_expiration = ts;

	ts = extract_timestamp(&s, "signature inception");
	if (ts < 0) return NULL;
	rr->sig_inception = ts;

	key_tag = extract_integer(&s, "key tag");
	if (key_tag < 0)	return NULL;
	rr->key_tag = key_tag;

	rr->signer = extract_name(&s, "signer name", 0);
	if (!rr->signer) return NULL;
	/* TODO validate signer name, http://tools.ietf.org/html/rfc4034#section-3.1.7 */

	sig = extract_base64_binary_data(&s, "signature");
	if (sig.length < 0)	return NULL;
	/* TODO validate signature length based on algorithm */
	rr->signature = sig;

	if (*s) {
		return bitch("garbage after valid RRSIG data");
	}
	G.dnssec_active = 1;
	return store_record(type, name, ttl, rr);
}

static char* rrsig_human(struct rr *rrv)
{
	// RRCAST(rrsig);
    // char s[1024];

    //snprintf(s, 1024, "SOA %s %s %d %d %d %d %d",
	 //    rr->mname, rr->rname, rr->serial,
	  //   rr->refresh, rr->retry, rr->expire, rr->minimum);
    //return quickstrdup_temp(s);
	return NULL;
}

static struct binary_data rrsig_wirerdata_ex(struct rr *rrv, int with_signature)
{
	RRCAST(rrsig);
	struct binary_data bd;

	bd = compose_binary_data("2114442d", 1,
		rr->type_covered, rr->algorithm, rr->labels,
		rr->orig_ttl, rr->sig_expiration, rr->sig_inception,
		rr->key_tag, name2wire_name(rr->signer));
	if (with_signature) {
		return compose_binary_data("dd", 1, bd, rr->signature);
	}
	return bd;
}

static struct binary_data rrsig_wirerdata(struct rr *rrv)
{
	return rrsig_wirerdata_ex(rrv, 1);
}

struct rr_with_wired
{
	struct rr *rr;
	struct binary_data wired;
};

static int compare_rr_with_wired(const void *va, const void *vb)
{
	const struct rr_with_wired *a = va;
	const struct rr_with_wired *b = vb;
	int r;

	if (a->wired.length == b->wired.length) {
		return memcmp(a->wired.data, b->wired.data, a->wired.length);
	} else if (a->wired.length < b->wired.length) {
		r = memcmp(a->wired.data, b->wired.data, a->wired.length);
		if (r != 0) return r;
		return -1;
	} else {
		r = memcmp(a->wired.data, b->wired.data, b->wired.length);
		if (r != 0) return r;
		return 1;
	}
}

static struct verification_data *verification_queue = NULL;
static int verification_queue_size = 0;
static pthread_mutex_t queue_lock;
static int workers_started = 0;
static pthread_t *workers;

void *verification_thread(void *dummy)
{
	struct verification_data *d;
	struct timespec sleep_time;

	while (1) {
		if (pthread_mutex_lock(&queue_lock) != 0)
			croak(1, "pthread_mutex_lock");
		d = verification_queue;
		if (d) {
			verification_queue = d->next;
			G.stats.signatures_verified++;
		}
		if (pthread_mutex_unlock(&queue_lock) != 0)
			croak(1, "pthread_mutex_unlock");
		if (d) {
			int r;
			d->next = NULL;
			r = EVP_VerifyFinal(&d->ctx, (unsigned char *)d->rr->signature.data, d->rr->signature.length, d->key->pkey);
			if (r == 1) {
				d->ok = 1;
			} else {
				d->openssl_error = ERR_peek_last_error();
			}
			if (pthread_mutex_lock(&queue_lock) != 0)
				croak(1, "pthread_mutex_lock");
			verification_queue_size--;
			if (pthread_mutex_unlock(&queue_lock) != 0)
				croak(1, "pthread_mutex_unlock");
		} else {
			sleep_time.tv_sec  = 0;
			sleep_time.tv_nsec = 10000000;
			nanosleep(&sleep_time, NULL);
		}
	}
}

static void start_workers(void)
{
	int i;

	if (workers_started)
		return;
	if (G.opt.verbose)
		fprintf(stderr, "starting workers for signature verification\n");
	workers = getmem(sizeof(*workers)*G.opt.n_threads);
	for (i = 0; i < G.opt.n_threads; i++) {
		if (pthread_create(&workers[i], NULL, verification_thread, NULL) != 0)
			croak(1, "pthread_create");
	}
	workers_started = 1;
}

static void schedule_verification(struct verification_data *d)
{
	int cur_size;
	if (G.opt.n_threads > 1) {
		if (pthread_mutex_lock(&queue_lock) != 0)
			croak(1, "pthread_mutex_lock");
		d->next = verification_queue;
		verification_queue = d;
		verification_queue_size++;
		cur_size = verification_queue_size;
		if (pthread_mutex_unlock(&queue_lock) != 0)
			croak(1, "pthread_mutex_unlock");
		if (!workers_started && cur_size >= G.opt.n_threads)
			start_workers();
	} else {
		int r;
		G.stats.signatures_verified++;
		r = EVP_VerifyFinal(&d->ctx, (unsigned char *)d->rr->signature.data, d->rr->signature.length, d->key->pkey);
		if (r == 1) {
			d->ok = 1;
		} else {
			d->openssl_error = ERR_peek_last_error();
		}
	}
}

static int verify_signature(struct verification_data *d, struct rr_set *signed_set)
{
	uint16_t b2;
	uint32_t b4;
	struct binary_data chunk;
	struct rr_with_wired *set;
	struct rr *signed_rr;
	int i;

	EVP_MD_CTX_init(&d->ctx);
	switch (d->rr->algorithm) {
	case ALG_DSA:
	case ALG_RSASHA1:
	case ALG_DSA_NSEC3_SHA1:
	case ALG_RSASHA1_NSEC3_SHA1:
		if (EVP_VerifyInit(&d->ctx, EVP_sha1()) != 1)
			return 0;
		break;
	case ALG_RSASHA256:
		if (EVP_VerifyInit(&d->ctx, EVP_sha256()) != 1)
			return 0;
		break;
	case ALG_RSASHA512:
		if (EVP_VerifyInit(&d->ctx, EVP_sha512()) != 1)
			return 0;
		break;
	default:
		return 0;
	}

	chunk = rrsig_wirerdata_ex(&d->rr->rr, 0);
	if (chunk.length < 0)
		return 0;
	EVP_VerifyUpdate(&d->ctx, chunk.data, chunk.length);

	set = getmem_temp(sizeof(*set) * signed_set->count);

	signed_rr = signed_set->tail;
	i = 0;
	while (signed_rr) {
		set[i].rr = signed_rr;
		set[i].wired = call_get_wired(signed_rr);
		if (set[i].wired.length < 0)
			return 0;
		i++;
		signed_rr = signed_rr->next;
	}
	qsort(set, signed_set->count, sizeof(*set), compare_rr_with_wired);

	for (i = 0; i < signed_set->count; i++) {
		chunk = name2wire_name(signed_set->named_rr->name);
		if (chunk.length < 0)
			return 0;
		EVP_VerifyUpdate(&d->ctx, chunk.data, chunk.length);
		b2 = htons(set[i].rr->rdtype);    EVP_VerifyUpdate(&d->ctx, &b2, 2);
		b2 = htons(1);  /* class IN */   EVP_VerifyUpdate(&d->ctx, &b2, 2);
		b4 = htonl(set[i].rr->ttl);       EVP_VerifyUpdate(&d->ctx, &b4, 4);
		b2 = htons(set[i].wired.length); EVP_VerifyUpdate(&d->ctx, &b2, 2);
		EVP_VerifyUpdate(&d->ctx, set[i].wired.data, set[i].wired.length);
	}

	schedule_verification(d);
	return 1;
}

static void *rrsig_validate(struct rr *rrv)
{
	RRCAST(rrsig);
	struct named_rr *named_rr;
	struct rr_set *signed_set;
	struct rr_dnskey *key = NULL;
	struct rr_set *dnskey_rr_set;
	int candidate_keys = 0;
	struct keys_to_verify *candidates;
	int i = 0;
	int t;

	named_rr = rr->rr.rr_set->named_rr;
	for (t = 0; t < G.opt.n_times_to_check; t++) {
		if (G.opt.times_to_check[t] < rr->sig_inception) {
			return moan(rr->rr.file_name, rr->rr.line, "%s signature is too new", named_rr->name);
		}
		if (G.opt.times_to_check[t] > rr->sig_expiration) {
			return moan(rr->rr.file_name, rr->rr.line, "%s signature is too old", named_rr->name);
		}
	}
	signed_set = find_rr_set_in_named_rr(named_rr, rr->type_covered);
	if (!signed_set) {
		return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG exists for non-existing type %s", named_rr->name, rdtype2str(rr->type_covered));
	}
	if (signed_set->tail->ttl != rr->orig_ttl) {
		return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG's original TTL differs from corresponding record's", named_rr->name);
	}
	dnskey_rr_set = find_rr_set(T_DNSKEY, rr->signer);
	if (!dnskey_rr_set) {
		return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG(%s): cannot find a signer key (%s)", named_rr->name, rdtype2str(rr->type_covered), rr->signer);
	}
	key = (struct rr_dnskey *)dnskey_rr_set->tail;
	while (key) {
		if (key->algorithm == rr->algorithm && key->key_tag == rr->key_tag) {
			candidate_keys++;
			dnskey_build_pkey(key);
		}
		key = (struct rr_dnskey *)key->rr.next;
	}
	if (candidate_keys == 0)
		return moan(rr->rr.file_name, rr->rr.line, "%s RRSIG(%s): cannot find the right signer key (%s)", named_rr->name, rdtype2str(rr->type_covered), rr->signer);

	candidates = getmem(sizeof(struct keys_to_verify) + (candidate_keys-1) * sizeof(struct verification_data));
	candidates->next = all_keys_to_verify;
	candidates->rr = rr;
	candidates->signed_set = signed_set;
	candidates->n_keys = candidate_keys;
	all_keys_to_verify = candidates;
	key = (struct rr_dnskey *)dnskey_rr_set->tail;
	while (key) {
		if (key->algorithm == rr->algorithm && key->key_tag == rr->key_tag) {
			candidates->to_verify[i].key = key;
			candidates->to_verify[i].rr = rr;
			candidates->to_verify[i].ok = 0;
			candidates->to_verify[i].openssl_error = 0;
			candidates->to_verify[i].next = NULL;
			i++;
		}
		key = (struct rr_dnskey *)key->rr.next;
	}

	return rr;
}

static pthread_mutex_t *lock_cs;
static long *lock_count;

static unsigned long pthreads_thread_id(void)
{
	unsigned long ret;

	ret=(unsigned long)pthread_self();
	return(ret);
}

static void pthreads_locking_callback(int mode, int type, char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}
}

void verify_all_keys(void)
{
	struct keys_to_verify *k = all_keys_to_verify;
	int i;
	struct timespec sleep_time;

	ERR_load_crypto_strings();
	if (G.opt.n_threads > 1) {
		lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
		lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
		for (i = 0; i < CRYPTO_num_locks(); i++) {
			lock_count[i] = 0;
			pthread_mutex_init(&lock_cs[i],NULL);
		}

		CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
		CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);

		if (pthread_mutex_init(&queue_lock, NULL) != 0)
			croak(1, "pthread_mutex_init");
	}

	while (k) {
		freeall_temp();
		for (i = 0; i < k->n_keys; i++) {
			if (dnskey_build_pkey(k->to_verify[i].key))
				verify_signature(&k->to_verify[i], k->signed_set);
		}
		k = k->next;
	}
	start_workers(); /* this is needed in case n_threads is greater than the number of signatures to verify */
	while (verification_queue_size > 0) {
		sleep_time.tv_sec  = 0;
		sleep_time.tv_nsec = 10000000;
		nanosleep(&sleep_time, NULL);
	}
	k = all_keys_to_verify;
	while (k) {
		int ok = 0;
		unsigned long e = 0;
		for (i = 0; i < k->n_keys; i++) {
			if (k->to_verify[i].ok) {
				ok = 1;
				break;
			} else {
				if (k->to_verify[i].openssl_error != 0)
					e = k->to_verify[i].openssl_error;
			}
		}
		if (!ok) {
			struct named_rr *named_rr;
			named_rr = k->rr->rr.rr_set->named_rr;
			moan(k->rr->rr.file_name, k->rr->rr.line, "%s RRSIG(%s): %s",
				 named_rr->name, rdtype2str(k->rr->type_covered),
				 e ? ERR_reason_error_string(e) : "cannot verify signature, reason unknown");
		}
		k = k->next;
	}
}

struct rr_methods rrsig_methods = { rrsig_parse, rrsig_human, rrsig_wirerdata, NULL, rrsig_validate };
