CC = gcc
CFLAGS += -O3 -Wall -Wextra -Wredundant-decls -Wvla -Wpointer-arith -O3 -fomit-frame-pointer
SOURCES = sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c
HEADERS = config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h reduce.h rounding.h symmetric.h randombytes.h
KECCAK_SOURCES = $(SOURCES) fips202.c symmetric-shake.c
KECCAK_HEADERS = $(HEADERS) fips202.h

all: test_dilithium key_gen Client/client Server/server

test_dilithium: test_dilithium.c randombytes.c $(KECCAK_SOURCES) $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -o $@ $< randombytes.c $(KECCAK_SOURCES)
	  
key_gen: key_gen.c randombytes.c $(KECCAK_SOURCES) $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -o $@ $< randombytes.c $(KECCAK_SOURCES)
	  
Client/client: client.c randombytes.c shared.c util.c $(KECCAK_SOURCES) $(KECCAK_HEADERS) | Client
	@echo "Creating server executable"
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -DSHA_BITS=384 -o $@ $< randombytes.c shared.c util.c -lcrypto -lsocket $(KECCAK_SOURCES)
		
Server/server: server.c randombytes.c shared.c util.c $(KECCAK_SOURCES) $(KECCAK_HEADERS) | Server
	@echo "Creating server executable"
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -DSHA_BITS=384 -o $@ $< randombytes.c shared.c util.c -lpthread -lcrypto -lsocket $(KECCAK_SOURCES)

clean:
	if [ -d "Server" ]; then rm -Rf Server; fi
	if [ -d "Client" ]; then rm -Rf Client; fi
	rm -f test_dilithium
	rm -f key_gen
	rm -f *.o
	
Server:
	mkdir -p $@
	
Client:
	mkdir -p $@

