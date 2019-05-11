CC=gcc
CFLAGS=-g -Wall
OFILES=noawareness.o md5.o string.o proc.o net.o
LFLAGS=-static
LIBS=-ljson-c -lssl -lcrypto

all:	noawareness

noawareness: $(OFILES)
	$(CC) $(CFLAGS) $(LFLAGS) $(OFILES) -o $@ $(LIBS)

%.o:%.c *.h
	$(CC) -c $(CFLAGS) $<

clean:
	rm -rf *.o *~ *.core noawareness

