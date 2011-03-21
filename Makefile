OPTIMIZE=-O2 -g
CFLAGS=-Wall

validns: main.o carp.o mempool.o
	cc $(CFLAGS) $(OPTIMIZE) -o validns main.o carp.o mempool.o -L/usr/local/lib -lJudy

clean:
	-rm validns main.o carp.o mempool.o
	-rm validns.core
	@echo ':-)'

main.o: main.c rr.h
	cc $(CFLAGS) $(OPTIMIZE) -c -o main.o main.c -I/usr/local/include

carp.o: carp.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o carp.o carp.c

mempool.o: mempool.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o mempool.o mempool.c

main.c: common.h carp.h mempool.h rr.h

carp.c: carp.h common.h

mempool.c: mempool.h carp.h

base64.c: base64.h

test:
	cc -Wall -O2 -o base64-test base64.c -DTEST_PROGRAM
	./base64-test
