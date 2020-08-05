CFLAGS += -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_LINUX)/include
LDFLAGS += -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/shared -lshared
LDFLAGS += -L$(SRCBASE)/nvram -lnvram

TARGET = dvqos
OBJS := dvqos.o do_cmd.o

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
