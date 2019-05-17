CC=gcc
CFLAGS=-g -Wall
OFILES=noawareness.o md5.o string.o proc.o net.o time.o netlink_events.o \
       inotify.o
LFLAGS=-static
LIBS=-ljson-c -lssl -lcrypto

all:	noawareness

noawareness: $(OFILES)
	$(CC) $(CFLAGS) $(LFLAGS) $(OFILES) -o $@ $(LIBS)

%.o:%.c *.h
	$(CC) -c $(CFLAGS) $<

clean:
	rm -rf *.o *~ *.core test_* noawareness

tests:
	gcc -c test-endswith.c
	gcc -o test_endswith string.o test-endswith.c
	./test_endswith
