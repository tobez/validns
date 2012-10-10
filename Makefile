OPTIMIZE=-O2 -g
CFLAGS=-Wall -Werror -pthread
INCPATH=-I/usr/local/include -I/opt/local/include
LDLIBS=-L/usr/local/lib -L/opt/local/lib -lJudy -lcrypto
CC?=cc

OBJS=	main.o carp.o mempool.o textparse.o base64.o base32hex.o \
	rr.o soa.o a.o cname.o mx.o ns.o \
	rrsig.o nsec.o dnskey.o txt.o aaaa.o \
	naptr.o srv.o nsec3param.o nsec3.o ds.o \
	hinfo.o loc.o nsec3checks.o ptr.o \
	sshfp.o threads.o rp.o spf.o cert.o \
	dname.o tlsa.o nid.o l32.o l64.o lp.o \
	ipseckey.o

validns: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(LDLIBS) $(OBJS) $(LDADD)

clean:
	-rm -f validns $(OBJS)
	-rm -f validns.core core
	@echo ':-)'

main.o: main.c common.h carp.h mempool.h textparse.h rr.h
carp.o: carp.c carp.h common.h
mempool.o: mempool.c mempool.h carp.h
textparse.o: textparse.c common.h carp.h mempool.h textparse.h base64.h
base64.o: base64.c base64.h
base32hex.o: base32hex.c base32hex.h
rr.o: rr.c common.h mempool.h carp.h textparse.h rr.h
soa.o: soa.c common.h textparse.h mempool.h carp.h rr.h
a.o: a.c common.h textparse.h mempool.h carp.h rr.h
cname.o: cname.c common.h textparse.h mempool.h carp.h rr.h
mx.o: mx.c common.h textparse.h mempool.h carp.h rr.h
ns.o: ns.c common.h textparse.h mempool.h carp.h rr.h
rrsig.o: rrsig.c common.h textparse.h mempool.h carp.h rr.h
nsec.o: nsec.c common.h textparse.h mempool.h carp.h rr.h
dnskey.o: dnskey.c common.h textparse.h mempool.h carp.h rr.h
txt.o: txt.c common.h textparse.h mempool.h carp.h rr.h
aaaa.o: aaaa.c common.h textparse.h mempool.h carp.h rr.h
naptr.o: naptr.c common.h textparse.h mempool.h carp.h rr.h
srv.o: srv.c common.h textparse.h mempool.h carp.h rr.h
nsec3param.o: nsec3param.c common.h textparse.h mempool.h carp.h rr.h
nsec3.o: nsec3.c common.h textparse.h mempool.h carp.h rr.h
ds.o: ds.c common.h textparse.h mempool.h carp.h rr.h
hinfo.o: hinfo.c common.h textparse.h mempool.h carp.h rr.h
loc.o: loc.c common.h textparse.h mempool.h carp.h rr.h
nsec3checks.o: nsec3checks.c common.h textparse.h mempool.h carp.h rr.h
ptr.o: ptr.c common.h textparse.h mempool.h carp.h rr.h
sshfp.o: sshfp.c common.h textparse.h mempool.h carp.h rr.h
rp.o: rp.c common.h textparse.h mempool.h carp.h rr.h
spf.o: spf.c common.h textparse.h mempool.h carp.h rr.h
cert.o: cert.c common.h textparse.h mempool.h carp.h rr.h
dname.o: dname.c common.h textparse.h mempool.h carp.h rr.h
tlsa.o: tlsa.c common.h textparse.h mempool.h carp.h rr.h
nid.o: nid.c common.h textparse.h mempool.h carp.h rr.h
l32.o: l32.c common.h textparse.h mempool.h carp.h rr.h
l64.o: l64.c common.h textparse.h mempool.h carp.h rr.h
lp.o: lp.c common.h textparse.h mempool.h carp.h rr.h
ipseckey.o: ipseckey.c common.h textparse.h mempool.h carp.h rr.h
threads.o: threads.c

.c.o:
	$(CC) $(CFLAGS) $(OPTIMIZE) -c $< -o $@ $(INCPATH)

test: validns
	perl -MTest::Harness -e 'runtests("t/test.pl")'

test-details: validns
	perl t/test.pl

test64:
	$(CC) -Wall -O2 -o base64-test base64.c -DTEST_PROGRAM
	./base64-test

test32hex:
	$(CC) -Wall -O2 -o base32hex-test base32hex.c -DTEST_PROGRAM
	./base32hex-test
