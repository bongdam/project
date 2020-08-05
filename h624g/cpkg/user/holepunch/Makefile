CFLAGS += -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_USERS)/boa/apmib
CFLAGS += -I$(DIR_LINUX)/drivers/net/wireless/rtl8192cd
CFLAGS += -I$(DIR_USERS)/boa/davolink

LDFLAGS += -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/nvram -lnvram
LDFLAGS += -L$(DIR_USERS)/boa/apmib -lapmib
LDFLAGS += -L$(SRCBASE)/laborer -lnmpipe
LDFLAGS += -L$(SRCBASE)/shared -lshared
LDFLAGS += -L$(DIR_USERS)/boa/davolink -lcustom

TARGET = holepunch
OBJS := holepunch.o holepunch_misc.o holepunch_vman.o

all: $(TARGET)

$(DIR_USERS)/boa/apmib/libapmib.so:
	$(MAKE) -C $(DIR_USERS)/boa apmib

$(TARGET): $(OBJS) $(DIR_USERS)/boa/apmib/libapmib.so
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
