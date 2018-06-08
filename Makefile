CC=gcc
LDFLAGS=-lpcap `pkg-config --libs libconfig`
CFLAGS=
EXEC=pac

all: $(EXEC)

pac: cb.o capture.o pac.o
		$(CC) -o pac pac.o capture.o cb.o $(LDFLAGS)

pac.o: pac.c
		$(CC) -o pac.o -c pac.c $(CFLAGS)

capture.o: capture.c
		$(CC) -o capture.o -c capture.c $(CFLAGS)

cb.o: cb.c
		$(CC) -o cb.o -c cb.c $(CFLAGS)

clean:
		rm -rf *.o

mrproper: clean
		rm -rf $(EXEC)
