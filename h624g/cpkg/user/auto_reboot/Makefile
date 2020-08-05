CFLAGS += -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(SRCBASE)/udhcp_skb

LDFLAGS += -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/nvram -lnvram

TARGET = auto_reboot
OBJS := auto_reboot.o igmp_list.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

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
