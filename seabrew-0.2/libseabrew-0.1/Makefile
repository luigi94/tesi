top_srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}
libdir = ${exec_prefix}/lib
includedir = ${prefix}/include

CC = gcc
CFLAGS  = -O3 -Wall \
	-I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
	 \
	-I/usr/include/pbc -I/usr/local/include/pbc \
	-DPACKAGE_NAME=\"seabrew\" -DPACKAGE_TARNAME=\"seabrew\" -DPACKAGE_VERSION=\"0.1\" -DPACKAGE_STRING=\"seabrew\ 0.1\" -DPACKAGE_BUGREPORT=\"sea@brew.edu\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DSTDC_HEADERS=1 -DHAVE_FCNTL_H=1 -DHAVE_STDDEF_H=1 -DHAVE_STRING_H=1 -DHAVE_STDLIB_H=1 -DHAVE_MALLOC=1 -DLSTAT_FOLLOWS_SLASHED_SYMLINK=1 -DHAVE_VPRINTF=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_STRCHR=1 -DHAVE_STRDUP=1 -DHAVE_MEMSET=1 -DHAVE_GMP=1 -DHAVE_PBC=1 -DHAVE_BSWABE=1
LDFLAGS = -O3 -Wall \
	-lglib-2.0 \
	-lgmp \
	-lpbc \
	-lbswabe \
	-lcrypto -lcrypto 

DISTNAME = seabrew-0.1

all: libseabrew.a TAGS

# compilation and library making

libseabrew.a: seabrew.o misc.o
	rm -f $@
	ar rc $@ $^

# test: test.o libseabrew.a
# 	$(CC) -o $@ $(LDFLAGS) $^

%.o: %.c *.h Makefile
	$(CC) -c -o $@ $< $(CFLAGS)

# installation

dist: AUTHORS COPYING INSTALL NEWS README \
	aclocal.m4 acinclude.m4 configure configure.ac Makefile.in \
	install-sh missing mkinstalldirs \
	seabrew.c misc.c private-bis.h seabrew.h
	rm -rf $(DISTNAME)
	mkdir $(DISTNAME)
	cp $^ $(DISTNAME)
	tar zc $(DISTNAME) > $(DISTNAME).tar.gz
	rm -rf $(DISTNAME)

install: libseabrew.a seabrew.h
	$(top_srcdir)/mkinstalldirs -m 755 $(DESTDIR)$(libdir)
	$(top_srcdir)/mkinstalldirs -m 755 $(DESTDIR)$(includedir)
	$(top_srcdir)/install-sh -m 755 libseabrew.a $(DESTDIR)$(libdir)
	$(top_srcdir)/install-sh -m 644 seabrew.h $(DESTDIR)$(includedir)

uninstall:
	/bin/rm -f $(DESTDIR)$(libdir)/libseabrew.a
	/bin/rm -f $(DESTDIR)$(includedir)/seabrew.h

# development and meta stuff

TAGS: *.c *.h
	@(etags $^ || true) 2> /dev/null

Makefile: Makefile.in config.status
	./config.status

config.status: configure
	./config.status --recheck

configure: configure.ac aclocal.m4
	autoconf

# cleanup

# remove everything an installing user can rebuild
clean:
	rm -rf *.o *.a $(DISTNAME) *.tar.gz TAGS *~

# remove everything a package developer can rebuild
distclean: clean
	rm -rf autom4te.cache Makefile config.status config.log config.cache \
		configure configure.scan autoscan*.log
