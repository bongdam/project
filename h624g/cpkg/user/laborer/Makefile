CFLAGS += -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_LINUX) -include $(DIR_LINUX)/include/generated/autoconf.h
CFLAGS += -I$(DIR_LINUX)/drivers/net/wireless/rtl8192cd
LDFLAGS += -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/shared -lshared
LDFLAGS += -L$(SRCBASE)/nvram -lnvram

TARGET = laborer
OBJS := cmd.o cpu_stat.o instrument.o link.o setphy.o eth_stat.o smart_wlreset.o snmp_trap.o main.o
OBJS += wlan_ifmng.o
ifeq ($(strip $(PROFILE)),GNT2100)
OBJS += ont_comm.o
endif
OBJS_lib := nmpipe.o

all: $(TARGET) libnmpipe.a

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	$(STRIP) --strip-all $@

libnmpipe.a: $(OBJS_lib)
	$(AR) ru $@ $^

clean:
	rm -f $(OBJS) $(OBJS_lib) $(TARGET) libnmpipe.a $(OBJS:%.o=.%.depend)

install: all
	@install -d $(INSTALLDIR)/usr/sbin
	@install $(TARGET) $(INSTALLDIR)/usr/sbin
	$(STRIP) $(INSTALLDIR)/usr/sbin/$(TARGET)

#romfs:
#	$(ROMFSINST) /bin/$(TARGET)

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
