vpath %.c core

include $(DIR_USERS)/.config
CFLAGS += -O2 -fomit-frame-pointer -Wall -DNDEBUG -Icore
LDFLAGS += -L$(STAGING_DIR)/lib -lytool -lnvram -lshared -lselect_event

TARGET = laborer
OBJS := cmd.o dev_event.o fifoserve.o instrument.o main.o
OBJS += conf.o cpu_stat.o inetup.o netif.o arping.o link.o dhcpc.o hotplug.o sysled.o
ifeq ($(CONFIG_APP_VPN_SERVER),y)
OBJS += vpn_check.o
CFLAGS_vpn_check := -I$(DIR_USERS)/boa/system
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(SLIBS)

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install: all
	@install -d $(INSTALLDIR)/usr/bin
	@install $(TARGET) $(INSTALLDIR)/usr/bin
	@install -m 755 hotplug-call $(INSTALLDIR)/usr/bin
	@install -d $(INSTALLDIR)/etc/hotplug.d

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS_$*) $(CFLAGS) -M $< > $@
	@echo -en "\t" >> $@
	@echo $(CC) $(CFLAGS_$*) $(CFLAGS) -c $< -o $*.o >> $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif

.PHONY: all clean install
