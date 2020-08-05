#
# arp_defender Makefile
#
#include $(DIR_LINUX)/.config

CFLAGS += -O2 -fomit-frame-pointer -Wall
LDFLAGS += -L$(SRCBASE)/libytool -lytool

TARGET = arp_defender
OBJS := arp_defender.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	$(STRIP) --strip-all $@

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	$(ROMFSINST) /bin/$(TARGET)

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
