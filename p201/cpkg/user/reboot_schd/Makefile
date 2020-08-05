CFLAGS += -g -O2 -fomit-frame-pointer -Wall
LDFLAGS += -L$(STAGING_DIR)/lib -lytool -lnvram

TARGET = reboot_schd
OBJS := reboot_schd.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install: all
	install -d $(INSTALLDIR)/usr/sbin
	install $(TARGET) $(INSTALLDIR)/usr/sbin

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS_$*) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif

.PHONY: all clean install
