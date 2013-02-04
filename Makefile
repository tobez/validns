# The following options seem to work fine on Linux, FreeBSD, and Darwin
OPTIMIZE=-O2 -g
CFLAGS=-Wall -Werror -pthread
INCPATH=-I/usr/local/include -I/opt/local/include -I/usr/local/ssl/include
CC?=cc

# These additional options work on Solaris/gcc to which I have an access
# (when combined with the options above, and CC=gcc).
#EXTRALPATH=-L/usr/local/ssl/lib -Wl,-R,/usr/local/ssl/lib
#EXTRALIBS=-lnsl -lrt

# According to Daniel Stirnimann, the following is needed
# to make it work on Solaris/cc.
#CFLAGS=-fast -xtarget=ultra3 -m64 -xarch=sparcvis2
#INCPATH=-I/opt/sws/include
#CC=cc
#EXTRALPATH=-L/opt/sws/lib/64 -R/opt/sws/lib/64
#EXTRALIBS-lrt -lnsl
#EXTRALINKING=-mt -lpthread

validns: main.o carp.o mempool.o textparse.o base64.o base32hex.o \
	rr.o soa.o a.o cname.o mx.o ns.o \
	rrsig.o nsec.o dnskey.o txt.o aaaa.o \
	naptr.o srv.o nsec3param.o nsec3.o ds.o \
	hinfo.o loc.o nsec3checks.o ptr.o \
	sshfp.o threads.o rp.o spf.o cert.o \
	dname.o tlsa.o nid.o l32.o l64.o lp.o \
	ipseckey.o
	$(CC) $(CFLAGS) $(OPTIMIZE) -o validns \
	    main.o carp.o mempool.o textparse.o base64.o base32hex.o \
	    rr.o soa.o a.o cname.o mx.o ns.o \
	    rrsig.o nsec.o dnskey.o txt.o aaaa.o \
	    naptr.o srv.o nsec3param.o nsec3.o ds.o \
	    hinfo.o loc.o nsec3checks.o ptr.o \
	    sshfp.o threads.o rp.o spf.o cert.o \
	    dname.o tlsa.o nid.o l32.o l64.o lp.o \
	    ipseckey.o \
	    -L/usr/local/lib -L/opt/local/lib $(EXTRALPATH) \
	    -lJudy -lcrypto $(EXTRALIBS) $(EXTRALINKING)

clean:
	-rm -f validns main.o carp.o mempool.o textparse.o
	-rm -f rr.o soa.o a.o cname.o mx.o ns.o
	-rm -f rrsig.o nsec.o dnskey.o txt.o aaaa.o
	-rm -f naptr.o srv.o nsec3param.o nsec3.o ds.o
	-rm -f hinfo.o loc.o nsec3checks.o ptr.o
	-rm -f sshfp.o base32hex.o base64.o threads.o
	-rm -f rp.o spf.o cert.o dname.o tlsa.o
	-rm -f nid.o l32.o l64.o lp.o ipseckey.o
	-rm -f validns.core core
	@echo ':-)'

main.o: main.c common.h carp.h mempool.h textparse.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o main.o main.c $(INCPATH)

carp.o: carp.c carp.h common.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o carp.o carp.c $(INCPATH)

mempool.o: mempool.c mempool.h carp.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o mempool.o mempool.c $(INCPATH)

textparse.o: textparse.c common.h carp.h mempool.h textparse.h base64.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o textparse.o textparse.c $(INCPATH)

base64.o: base64.c base64.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o base64.o base64.c $(INCPATH)

base32hex.o: base32hex.c base32hex.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o base32hex.o base32hex.c $(INCPATH)

rr.o: rr.c common.h mempool.h carp.h textparse.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o rr.o rr.c $(INCPATH)

soa.o: soa.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o soa.o soa.c $(INCPATH)

a.o: a.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o a.o a.c $(INCPATH)

cname.o: cname.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o cname.o cname.c $(INCPATH)

mx.o: mx.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o mx.o mx.c $(INCPATH)

ns.o: ns.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o ns.o ns.c $(INCPATH)

rrsig.o: rrsig.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o rrsig.o rrsig.c $(INCPATH)

nsec.o: nsec.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o nsec.o nsec.c $(INCPATH)

dnskey.o: dnskey.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o dnskey.o dnskey.c $(INCPATH)

txt.o: txt.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o txt.o txt.c $(INCPATH)

aaaa.o: aaaa.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o aaaa.o aaaa.c $(INCPATH)

naptr.o: naptr.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o naptr.o naptr.c $(INCPATH)

srv.o: srv.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o srv.o srv.c $(INCPATH)

nsec3param.o: nsec3param.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o nsec3param.o nsec3param.c $(INCPATH)

nsec3.o: nsec3.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o nsec3.o nsec3.c $(INCPATH)

ds.o: ds.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o ds.o ds.c $(INCPATH)

hinfo.o: hinfo.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o hinfo.o hinfo.c $(INCPATH)

loc.o: loc.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o loc.o loc.c $(INCPATH)

nsec3checks.o: nsec3checks.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o nsec3checks.o nsec3checks.c $(INCPATH)

ptr.o: ptr.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o ptr.o ptr.c $(INCPATH)

sshfp.o: sshfp.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o sshfp.o sshfp.c $(INCPATH)

rp.o: rp.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o rp.o rp.c $(INCPATH)

spf.o: spf.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o spf.o spf.c $(INCPATH)

cert.o: cert.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o cert.o cert.c $(INCPATH)

dname.o: dname.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o dname.o dname.c $(INCPATH)

tlsa.o: tlsa.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o tlsa.o tlsa.c $(INCPATH)

nid.o: nid.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o nid.o nid.c $(INCPATH)

l32.o: l32.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o l32.o l32.c $(INCPATH)

l64.o: l64.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o l64.o l64.c $(INCPATH)

lp.o: lp.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o lp.o lp.c $(INCPATH)

ipseckey.o: ipseckey.c common.h textparse.h mempool.h carp.h rr.h
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o ipseckey.o ipseckey.c $(INCPATH)

threads.o: threads.c
	$(CC) $(CFLAGS) $(OPTIMIZE) -c -o threads.o threads.c $(INCPATH)

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
