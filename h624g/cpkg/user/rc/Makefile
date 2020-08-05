CFLAGS += -O2 -fomit-frame-pointer -Wall
LDFLAGS += -L$(SRCBASE)/libytool -lytool -L$(SRCBASE)/shared -lshared

TARGET = rc
OBJS := init.o rc.o interface.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install: all
	install -d $(INSTALLDIR)/sbin
	install $(TARGET) $(INSTALLDIR)/sbin
	$(STRIP) $(INSTALLDIR)/sbin/$(TARGET)
	cd $(INSTALLDIR)/sbin && ln -sf rc init
	cd $(INSTALLDIR)/sbin && ln -sf rc erase
#	cd $(INSTALLDIR)/sbin && ln -sf rc write
#	cd $(INSTALLDIR)/sbin && ln -sf rc stats
	cd $(INSTALLDIR)/sbin && ln -sf rc preinit

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
