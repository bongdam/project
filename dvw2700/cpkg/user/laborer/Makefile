include $(DIR_USERS)/.config

vpath %.c core

CFLAGS += -O2 -fomit-frame-pointer -Wall -DNDEBUG
CFLAGS += -I./core -include $(DIR_LINUX)/include/generated/autoconf.h
CFLAGS += -I$(DIR_LINUX)/drivers/net/wireless/rtl8192cd
LDFLAGS += -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/shared -lshared
LDFLAGS += -L$(SRCBASE)/nvram -lnvram
CFLAGS += -I$(SRCBASE)/libselect_event
LDFLAGS += -L$(SRCBASE)/libselect_event -lselect_event

TARGET = laborer
OBJS := cmd.o dev_event.o fifoserve.o instrument.o nmpipe.o main.o
OBJS += cpu_stat.o netif.o link.o led.o patch_wfq.o arping.o gwka.o garp.o tstamp.o

# tiny httpd server: serves only file
ifeq ($(strip $(CONFIG_LABORER_JOB_WEBRD)),y)
OBJS += stream_frag.o httpd.o fdnsd.o
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

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
