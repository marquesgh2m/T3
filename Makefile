CC=gcc
CFLAGS=-I. -O2 -Wall
DEPS = tunnel.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

testtunnel: testtunnel.o tunnel.o
	$(CC) -o testtunnel tunnel.o testtunnel.o $(CFLAGS)

all: icmptunnel

clean:
	rm -f *.o testtunnel
