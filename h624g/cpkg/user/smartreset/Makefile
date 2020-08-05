CFLAGS += -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_LINUX)/drivers/net/wireless/rtl8192cd
CFLAGS += -I$(DIR_USERS)/boa/apmib -I$(DIR_USERS)/boa/davolink
LDFLAGS += -L$(DIR_USERS)/boa/apmib -lapmib -L$(DIR_USERS)/boa/davolink -lcustom
LDFLAGS += -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/nvram -lnvram
LDFLAGS += -L$(SRCBASE)/shared -lshared

TARGET = smartreset
OBJS := dosmartreset.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	$(STRIP) --strip-all $@

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
