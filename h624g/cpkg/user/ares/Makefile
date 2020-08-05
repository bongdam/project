CFLAGS += -DLGDACOM_PROVIS -fomit-frame-pointer -W -Wall -Wstrict-prototypes
CFLAGS += -fPIC

OBJS :=	ares__close_sockets.o ares__get_hostent.o ares__read_line.o \
	ares_destroy.o ares_expand_name.o ares_fds.o ares_free_errmem.o \
	ares_free_hostent.o ares_free_string.o ares_gethostbyaddr.o \
	ares_gethostbyname.o ares_init.o ares_mkquery.o ares_parse_a_reply.o \
	ares_parse_ptr_reply.o ares_process.o ares_query.o ares_search.o \
	ares_send.o ares_strerror.o ares_timeout.o lg_gethostbyname.o \
	bulk_gethostbyname.o

all: libares.so aprovis

clean:
	rm -f *.o aprovis libares.a libares.so .*.depend

install: all 
	install -d $(INSTALLDIR)/usr/sbin
	install -d $(INSTALLDIR)/usr/lib
	install aprovis $(INSTALLDIR)/usr/sbin
	install libares.so $(INSTALLDIR)/usr/lib
	$(STRIP) $(INSTALLDIR)/usr/sbin/aprovis

libares.a: $(OBJS)
	$(AR) cru $@ $(OBJS)
	$(RANLIB) $@

libares.so: $(OBJS)
	$(CC) -shared -o $@ $(CFLAGS) $(LDFLAGS) $(OBJS)
	$(STRIP) $@

aprovis.o: .aprovis.depend

aprovis: aprovis.o 
	$(CC) -o $@ $< $(LDFLAGS) -l ares -L .

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
