OPTIMIZE=-O2
CFLAGS=-Wall

validness: main.o carp.o
	cc $(CFLAGS) -o validness main.o carp.o -L/usr/local/lib -lJudy

main.o: main.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o main.o main.c -I/usr/local/include

carp.o: carp.c
	cc $(CFLAGS) $(OPTIMIZE) -c -o carp.o carp.c
