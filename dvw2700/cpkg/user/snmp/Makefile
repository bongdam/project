CFLAGS += -g -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(shell pwd)/engine
CFLAGS += -I$(DIR_USERS)/boa/apmib -I$(DIR_USERS)/auth/include -I$(DIR_USERS)/boa/davolink
CFLAGS += -I$(DIR_LINUX)/drivers/net/wireless/rtl8192cd
CFLAGS += -I$(SRCBASE)/udhcp

LDFLAGS = -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/nvram -lnvram
LDFLAGS += -L$(SRCBASE)/laborer -lnmpipe
LDFLAGS += -L$(DIR_USERS)/boa/apmib -lapmib -L$(DIR_USERS)/boa/davolink -lcustom
LDFLAGS += -L$(SRCBASE)/furl -lfurl -L$(SRCBASE)/shared -lshared

TARGET = snmp

SNMP := snmp_main.o cjhv_api.o cjhv_mib.o snmp_ioctl.o snmp_trap.o

ENGINE := engine/agt_mib.o engine/agt_engine.o engine/asn1.o engine/snmp_community.o engine/snmp_strcasecmp.o

OBJS := $(SNMP) $(ENGINE)

all : $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	install -m 755 $(TARGET) $(INSTALLDIR)/bin
	$(STRIP) $(INSTALLDIR)/bin/$(TARGET)

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
