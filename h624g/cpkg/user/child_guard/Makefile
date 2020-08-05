CFLAGS += -s -O2 -fomit-frame-pointer -Wall
LDFLAGS += -L$(SRCBASE)/libytool -lytool -L$(SRCBASE)/shared -lshared
LDFLAGS += -L$(SRCBASE)/nvram -lnvram

TARGET = child_guard
OBJS := child_guard.o

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
