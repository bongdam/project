CFLAGS += -O2 -fomit-frame-pointer -Wall
CFLAGS += -Wextra -Wstrict-prototypes -Wdeclaration-after-statement
CFLAGS += -D_GNU_SOURCE -DDEBUG -DIPTABLES_143
CFLAGS += -I. -I$(DIR_USERS)/iptables-1.4.4/include
LIBS += $(DIR_USERS)/iptables-1.4.4/libiptc/.libs/libiptc.a
LDFLAGS += -L$(STAGING_DIR)/lib -lytool

EXE1 = miniupnpd
EXE2 = upnpctrl

BASEOBJS = miniupnpd.o upnphttp.o upnpdescgen.o upnpsoap.o \
		   upnpreplyparse.o minixml.o \
		   upnpredirect.o getifaddr.o daemonize.o upnpglobalvars.o \
		   options.o upnppermissions.o minissdp.o natpmp.o pcpserver.o \
		   upnpevents.o upnputils.o getconnstatus.o \
		   upnppinhole.o asyncsendto.o portinuse.o

LNXOBJS = linux/getifstats.o linux/ifacewatcher.o
NETFILTEROBJS = netfilter/iptcrdr.o netfilter/iptpinhole.o netfilter/nfct_get.o

OBJS = $(BASEOBJS) $(LNXOBJS) $(NETFILTEROBJS)

all: $(EXE1) $(EXE2)

$(EXE1): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS) $(LDFLAGS)

$(EXE2): genuuid upnpctrl.o
	$(CC) -o $@ upnpctrl.o $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(EXE1) $(EXE2) $(OBJS:%.o=.%.depend)

install:
	install -d $(INSTALLDIR)/bin
	install $(EXE1) $(INSTALLDIR)/bin
	install $(EXE2) $(INSTALLDIR)/bin

genuuid:
	sed -i -e "s/^static\s*char\s*uuid\[\]\s*=\s*\"[-0-9a-f]*\"/static char uuid[] = \"`(genuuid||uuidgen||uuid) 2>/dev/null`\"/" upnpctrl.c
	touch $@

%.o: .%.depend
.%.depend: %.c
	@$(CC) $(CFLAGS) -M $< > $@
	@echo -en "\t" >> $@
	@echo $(CC) $(CFLAGS_$*) $(CFLAGS) -c $*.c -o $*.o >> $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
