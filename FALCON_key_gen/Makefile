CC = gcc
CFLAGS += -O3 -Wall -Wextra -Wredundant-decls -Wvla -Wpointer-arith -fomit-frame-pointer

SOURCES = codec.c common.c fft.c fpr.c keygen.c nist.c rng.c shake.c sign.c vrfy.c katrng.c
HEADERS = api.h fpr.h inner.h katrng.h

all: key_gen
	  
key_gen: key_gen.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DFALCON_MODE=5 -o $@ $< $(SOURCES)
	
clean:
	rm -f key_gen
	rm -f *.o
