CFLAGS += -Os -Wall -Wno-unused-result -I. -Ilibs
TARGET = nvram
OBJS := main.o

all: libnvram $(TARGET)

$(TARGET): libs/libnvram.so $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -Llibs -lnvram

libnvram:
	$(MAKE) -C libs

clean:
	@$(MAKE) -C libs clean
	@rm -f $(TARGET) $(OBJS)

install: all
	@$(MAKE) -C libs $@
	install -d $(INSTALLDIR)/usr/bin
	install $(TARGET) $(INSTALLDIR)/usr/bin/$(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: all clean install libnvram
