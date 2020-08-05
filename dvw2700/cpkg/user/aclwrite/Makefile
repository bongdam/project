
CFLAGS += -g -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_LINUX)/include/net/rtl -I$(CPKG_USER)/include -include $(DIR_LINUX)/include/generated/autoconf.h

TARGET = aclwrite
OBJS := aclwrite.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	$(STRIP) --strip-all $@

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	install -d $(INSTALLDIR)/usr/sbin
	install $(TARGET) $(INSTALLDIR)/usr/sbin

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
