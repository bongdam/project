#
# Davolink add files 2013-10-19
#
# Object
# 1. for davolink specific commands
#

CFLAGS += -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_USERS)/boa/apmib
CFLAGS += -I$(DIR_LINUX)/drivers/net/wireless/rtl8192cd

LDFLAGS += -L$(SRCBASE)/libytool -lytool -L$(SRCBASE)/shared -lshared
LDFLAGS += -L$(SRCBASE)/nvram -lnvram -L$(SRCBASE)/furl -lfurl
LDFLAGS += -L$(DIR_USERS)/boa/apmib -lapmib

TARGET = ldap
OBJS := ldap.o 

all: $(TARGET)

$(DIR_USERS)/boa/apmib/libapmib.so:
	$(MAKE) -C $(DIR_USERS)/boa apmib

$(TARGET): $(OBJS) $(DIR_USERS)/boa/apmib/libapmib.so
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
#	$(STRIP) --strip-all $@

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

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
