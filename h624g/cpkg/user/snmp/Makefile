CFLAGS += -O2 -fomit-frame-pointer -Wall #-Wno-pointer-sign
CFLAGS += -I$(shell pwd)/engine
CFLAGS += -I$(DIR_USERS)/boa/apmib -I$(DIR_USERS)/auth/include -I$(DIR_USERS)/boa/davolink
CFLAGS += -I$(DIR_LINUX)/drivers/net/wireless/rtl8192cd
CFLAGS += -I$(SRCBASE)/udhcp_skb
#jihyun@davo160202 jcode#7 +
CFLAGS += -D__STATRAP_EVENT__
#-

LDFLAGS += -L$(SRCBASE)/laborer -lnmpipe
LDFLAGS += -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/nvram -lnvram
LDFLAGS += -L$(DIR_USERS)/boa/apmib -lapmib -L$(DIR_USERS)/boa/davolink -lcustom
LDFLAGS += -L$(SRCBASE)/laborer -lnmpipe
LDFLAGS += -L$(SRCBASE)/furl -lfurl -L$(SRCBASE)/shared -lshared

TARGET = snmp

$(DIR_USERS)/boa/apmib/libapmib.so:
	$(MAKE) -C $(DIR_USERS)/boa apmib


SNMP := snmp_main.o skbb.o misc.o snmp_trap.o snmp_response.o skbb_api.o sta_mon.o snmp_value.o cpe_ping.o
SNMP += snmp_traptype.o

ENGINE:= engine/agt_mib.o engine/agt_engine.o engine/snmp_community.o engine/asn1.o

OBJS := $(SNMP) $(ENGINE)

all : apmib_defs $(TARGET)

apmib_defs:
	@$(MAKE) -C $(DIR_USERS)/boa $@

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) -ldl
	$(STRIP) --strip-all $@ 	# add 0413

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install: all
	install -d $(INSTALLDIR)/usr/sbin
	install $(TARGET) $(INSTALLDIR)/usr/sbin
	$(STRIP) $(INSTALLDIR)/usr/sbin/$(TARGET)

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
