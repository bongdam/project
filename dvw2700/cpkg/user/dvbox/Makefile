include $(DIR_USERS)/busybox/.config

CFLAGS += -s -O2 -fomit-frame-pointer -Wall -I$(SRCBASE)/libselect_event
LDFLAGS += -L$(SRCBASE)/libytool -lytool -L$(SRCBASE)/shared -lshared
LDFLAGS += -L$(SRCBASE)/laborer -lnmpipe
LDFLAGS += -L$(SRCBASE)/nvram -lnvram
LDFLAGS += -L$(SRCBASE)/furl -lfurl

TARGET = dvbox
OBJS := main.o common.o dvflag.o mping.o md.o gpio.o phyconfig.o preq.o ub.o mirror.o
ifneq ($(strip $(CONFIG_WGET)),)
OBJS += furl.o
endif
OBJS += wmmmap.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	install -m 755 $(TARGET) $(INSTALLDIR)/bin
	$(STRIP) $(INSTALLDIR)/bin/$(TARGET)
	@for i in $(shell $(CROSS_COMPILE)nm $(TARGET) | grep __applet_entry__ | sed 's/.*__applet_entry__//'); do \
		ln -sf $(TARGET) $(INSTALLDIR)/bin/$$i; \
	done

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
