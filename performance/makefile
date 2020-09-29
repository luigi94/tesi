OBJS = ./src/common.o ./src/core.o ./src/misc.o ./src/policy_lang.o ./src/util.o ./src/shared.o

CC = gcc

SRC = src

CFLAGS = -O3 -Wall -Wextra -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/pbc -I/usr/local/include/pbc -DPACKAGE_NAME=\"cpabe\" -DPACKAGE_TARNAME=\"cpabe\" -DPACKAGE_VERSION=\"0.11\" -DPACKAGE_STRING=\"cpabe\ 0.11\" -DPACKAGE_BUGREPORT=\"bethenco@cs.berkeley.edu\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DSTDC_HEADERS=1 -DHAVE_FCNTL_H=1 -DHAVE_STDDEF_H=1 -DHAVE_STRING_H=1 -DHAVE_STDLIB_H=1 -DHAVE_MALLOC=1 -DLSTAT_FOLLOWS_SLASHED_SYMLINK=1 -DHAVE_VPRINTF=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_STRCHR=1 -DHAVE_STRDUP=1 -DHAVE_MEMSET=1 -DHAVE_GMP=1 -DHAVE_PBC=1 -DHAVE_BSWABE=1 

LDFLAGS = -O3 -Wall -Wextra -lglib-2.0 -Wl,-rpath /usr/local/lib -Wl,-rpath /usr/local/lib -lpbc -lbswabe -lcrypto -lgmp -lnsl -lsocket

TARGETS = Client/client Server/server

$(SRC)/common.o: $(SRC)/common.c $(SRC)/common.h
	@echo "Compiling common.c"
	$(CC) -c -o $@ $< $(CFLAGS)
	
$(SRC)/core.o: $(SRC)/core.c $(SRC)/bswabe.h $(SRC)/common.h $(SRC)/private.h
	@echo "Compiling core.c"
	$(CC) -c -o $@ $< $(CFLAGS)
	
$(SRC)/misc.o: $(SRC)/misc.c $(SRC)/bswabe.h $(SRC)/private.h
	@echo "Compiling misc.c"
	$(CC) -c -o $@ $< $(CFLAGS)
	
$(SRC)/policy_lang.o: $(SRC)/policy_lang.c $(SRC)/policy_lang.h $(SRC)/common.h
	@echo "Compiling policy_lang.c"
	$(CC) -c -o $@ $< $(CFLAGS)

$(SRC)/util.o: $(SRC)/util.c $(SRC)/util.h
	@echo "Compiling util.c"
	$(CC) -c -o $@ $< $(CFLAGS)
	
$(SRC)/db.o: $(SRC)/db.c $(SRC)/db.h
	@echo "Compiling db.c"
	$(CC) -c -o $@ $< $(CFLAGS)
	
$(SRC)/shared.o: $(SRC)/shared.c $(SRC)/shared.h
	@echo "Compiling shared.c"
	$(CC) -c -o $@ $< $(CFLAGS)
	
$(SRC)/client.o: $(SRC)/$(client) $(SRC)/bswabe.h $(SRC)/private.h $(SRC)/common.h $(SRC)/util.h $(SRC)/shared.h
	@echo "Compiling client.c"
	$(CC) -c -o $@ $< $(CFLAGS)
	
$(SRC)/server.o: $(SRC)/$(server) $(SRC)/bswabe.h $(SRC)/private.h $(SRC)/common.h $(SRC)/util.h $(SRC)/db.h $(SRC)/shared.h
	@echo "Compiling server.c"
	$(CC) -c -o $@ $< $(CFLAGS)
	
Client/client: $(OBJS) $(SRC)/client.o | Client
	@echo "Creating client executable"
	$(CC) -o $@ $^ $(LDFLAGS)
	
Server/server: $(OBJS) $(SRC)/db.o $(SRC)/server.o | Server
	 @echo "Creating server executable"
	$(CC) -o $@ $^ $(LDFLAGS) -lsqlite3 -pthread
	
all: $(TARGETS)

clean:
	rm -f Client/* Server/* $(SRC)/*.o

Client:
	mkdir -p $@

Server:
	mkdir -p $@ 
