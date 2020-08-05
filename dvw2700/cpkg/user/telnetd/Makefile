CFLAGS += -g -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_USER)/boa/apmib
LDFLAGS = -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/nvram -lnvram
LDFLAGS += -L$(SRCBASE)/libkcapi -lkcapi

TARGET = telnetd
OBJS := telnetd.o tlogin.o bbwrap.o

.PHONY: clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	install -m 755 $(TARGET) $(INSTALLDIR)/bin
	$(STRIP) $(INSTALLDIR)/bin/$(TARGET)

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
