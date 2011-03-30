OPTIMIZE=-O2 -g
CFLAGS=-Wall
INCPATH=-I/usr/local/include

validns: main.o carp.o mempool.o textparse.o base64.o \
	rr.o soa.o a.o cname.o mx.o ns.o \
	rrsig.o nsec.o dnskey.o txt.o aaaa.o \
	naptr.o srv.o nsec3param.o nsec3.o
	cc $(CFLAGS) $(OPTIMIZE) -o validns \
	    main.o carp.o mempool.o textparse.o base64.o \
	    rr.o soa.o a.o cname.o mx.o ns.o \
	    rrsig.o nsec.o dnskey.o txt.o aaaa.o \
	    naptr.o srv.o nsec3param.o nsec3.o \
	    -L/usr/local/lib -lJudy

clean:
	-rm validns main.o carp.o mempool.o textparse.o
	-rm rr.o soa.o a.o cname.o mx.o ns.o
	-rm rrsig.o nsec.o dnskey.o txt.o aaaa.o
	-rm naptr.o srv.o nsec3param.o nsec3.o
	-rm validns.core
	@echo ':-)'

main.o: main.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o main.o main.c $(INCPATH)

carp.o: carp.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o carp.o carp.c $(INCPATH)

mempool.o: mempool.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o mempool.o mempool.c $(INCPATH)

textparse.o: textparse.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o textparse.o textparse.c $(INCPATH)

base64.o: base64.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o base64.o base64.c $(INCPATH)

rr.o: rr.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o rr.o rr.c $(INCPATH)

soa.o: soa.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o soa.o soa.c $(INCPATH)

a.o: a.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o a.o a.c $(INCPATH)

cname.o: cname.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o cname.o cname.c $(INCPATH)

mx.o: mx.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o mx.o mx.c $(INCPATH)

ns.o: ns.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o ns.o ns.c $(INCPATH)

rrsig.o: rrsig.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o rrsig.o rrsig.c $(INCPATH)

nsec.o: nsec.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o nsec.o nsec.c $(INCPATH)

dnskey.o: dnskey.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o dnskey.o dnskey.c $(INCPATH)

txt.o: txt.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o txt.o txt.c $(INCPATH)

aaaa.o: aaaa.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o aaaa.o aaaa.c $(INCPATH)

naptr.o: naptr.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o naptr.o naptr.c $(INCPATH)

srv.o: srv.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o srv.o srv.c $(INCPATH)

nsec3param.o: nsec3param.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o nsec3param.o nsec3param.c $(INCPATH)

nsec3.o: nsec3.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o nsec3.o nsec3.c $(INCPATH)

main.c: common.h carp.h mempool.h rr.h

carp.c: carp.h common.h

mempool.c: mempool.h carp.h

textparse.c: common.h

base64.c: base64.h

rr.c: common.h carp.h mempool.h rr.h

soa.c: common.h rr.h

a.c: common.h rr.h

cname.c: common.h rr.h

mx.c: common.h rr.h

ns.c: common.h rr.h

rrsig.c: common.h rr.h

nsec.c: common.h rr.h

dnskey.c: common.h rr.h

txt.c: common.h rr.h

aaaa.c: common.h rr.h

naptr.c: common.h rr.h

srv.c: common.h rr.h

nsec3param.c: common.h rr.h

nsec3.c: common.h rr.h

common.h: textparse.h carp.h mempool.h

test:
	perl -MTest::Harness -e 'runtests("t/test.pl")'

test-details:
	perl t/test.pl

test64:
	cc -Wall -O2 -o base64-test base64.c -DTEST_PROGRAM
	./base64-test
