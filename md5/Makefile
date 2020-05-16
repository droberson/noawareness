# Makefile for MD5 from rfc1321 code

CCF = -O -DMD=5

md5c.o: md5.h global.h
	gcc $(CCF) -c md5c.c

clean:
	rm -f *.o core

