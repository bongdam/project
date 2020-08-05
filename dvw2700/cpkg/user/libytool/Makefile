CFLAGS += -fpic -Os -fomit-frame-pointer -Wall
TARGET = libytool.so
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))

all: $(TARGET)

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
