CC=gcc
CFLAGS=-g -Wall
OFILES=noawareness.o md5.o string.o proc.o net.o time.o netlink_events.o \
       inotify.o error.o
LFLAGS=
#LFLAGS=-static
LIBS=-ljson-c

MD5_OBJ=md5/md5c.o

all:	$(MD5_OBJ) noawareness

%.o:%.c *.h
	$(CC) -c $(CFLAGS) $<

md5obj: md5/md5c.c
	@( cd md5; make )

noawareness: $(OFILES) md5obj
	$(CC) $(CFLAGS) $(MD5_OBJ) $(LFLAGS) $(OFILES) -o $@ $(LIBS)

clean:
	rm -rf *.o *~ *.core test_* noawareness
	@( cd md5; make clean )

tests:
	gcc -c test-endswith.c
	gcc -o test_endswith string.o test-endswith.c
	./test_endswith
