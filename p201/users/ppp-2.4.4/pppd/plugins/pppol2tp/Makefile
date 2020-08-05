#CC	= gcc
COPTS	= -O2 -g
CFLAGS	= $(COPTS) -I. -I../.. -I../../../include -fPIC
LDFLAGS	= -shared
INSTALL	= install

#***********************************************************************

DESTDIR = /usr/local
LIBDIR = $(DESTDIR)/lib/pppd/$(VERSION)

VERSION = $(shell awk -F '"' '/VERSION/ { print $$2; }' ../../patchlevel.h)

PLUGINS := pppol2tp.so openl2tp.so

#all: $(PLUGINS)
all: libl2tpplugin.a

libl2tpplugin.a: pppol2tp.o openl2tp.o
	$(AR) -rc $@ $^

%.so: %.o
	$(CC) $(CFLAGS) -o $@ -shared $^ $(LIBS)

install: all
	$(INSTALL) -d -m 755 $(LIBDIR)
	$(INSTALL) -c -m 755 $(PLUGINS) $(LIBDIR)

clean:
	rm -f *.o *.so *.a

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
