OBJS = ./src/common.o ./src/core.o ./src/misc.o ./src/policy_lang.o ./src/util.o
CC = gcc
SRC = src
CFLAGS  = -O3 -Wall -Wextra\
	-I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
	 \
	-I/usr/include/pbc -I/usr/local/include/pbc \
	 \
	-DPACKAGE_NAME=\"cpabe\" -DPACKAGE_TARNAME=\"cpabe\" -DPACKAGE_VERSION=\"0.11\" -DPACKAGE_STRING=\"cpabe\ 0.11\" -DPACKAGE_BUGREPORT=\"bethenco@cs.berkeley.edu\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DSTDC_HEADERS=1 -DHAVE_FCNTL_H=1 -DHAVE_STDDEF_H=1 -DHAVE_STRING_H=1 -DHAVE_STDLIB_H=1 -DHAVE_MALLOC=1 -DLSTAT_FOLLOWS_SLASHED_SYMLINK=1 -DHAVE_VPRINTF=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_STRCHR=1 -DHAVE_STRDUP=1 -DHAVE_MEMSET=1 -DHAVE_GMP=1 -DHAVE_PBC=1 -DHAVE_BSWABE=1 
LDFLAGS = -O3 -Wall -Wextra \
	-lglib-2.0 \
	-Wl,-rpath /usr/local/lib -lgmp \
	-Wl,-rpath /usr/local/lib -lpbc \
	-lbswabe \
	-lcrypto -lcrypto  \
	-lgmp \
	-lnsl -lsocket

TARGETS = Client/client Server/server

$(SRC)/%.o: $(SRC)/%.c $(SRC)/*.h
	$(CC) -c -o $@ $< $(CFLAGS)
	
Client/client: $(OBJS) $(SRC)/client.o | Client
	$(CC) -o $@ $^ $(LDFLAGS) 
	
Server/server: $(OBJS) $(SRC)/server.o | Server
	$(CC) -o $@ $^ $(LDFLAGS) -pthread
	
all: $(TARGETS)

clean:
	rm -f $(OBJS) $(TARGETS) ./src/*.o

Client:
	mkdir -p $@
    
Server:
	mkdir -p $@ 
