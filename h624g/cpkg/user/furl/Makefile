CFLAGS += -fpic -Os -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_LINUX)/drivers/net/wireless/rtl8192cd -I$(DIR_USERS)/boa/apmib
LDFLAGS = -L$(SRCBASE)/nvram -lnvram

TARGET = libfurl.so
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))

.PHONY: clean install apmib_defs

all: apmib_defs $(TARGET)

apmib_defs:
	@$(MAKE) -C $(DIR_USERS)/boa $@

$(TARGET): $(OBJS)
	$(CC) -shared -Wl,-soname,$(TARGET) -o $(TARGET) $(OBJS)

clean:
	@rm -f $(TARGET) $(OBJS) $(OBJS:%.o=.%.depend)

install: all
	install -d $(INSTALLDIR)/usr/lib
	install -m 755 $(TARGET) $(INSTALLDIR)/usr/lib
	$(STRIP) $(INSTALLDIR)/usr/lib/$(TARGET)

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
