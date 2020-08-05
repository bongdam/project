#
# arprobe Makefile
#

include $(DIR_LINUX)/.config

CFLAGS += -O2 -fomit-frame-pointer -Wall
LDFLAGS += -L$(SRCBASE)/libytool -lytool

TARGET = arprobe
OBJS := arprobe.o

ifeq ($(CONFIG_IPV6),y)
TARGET2 = dadd
OBJS2 := nd_send_ns.o nd_recv_na.o
endif

all: $(TARGET) $(TARGET2)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	$(STRIP) --strip-all $@

ifeq ($(CONFIG_IPV6),y)
$(TARGET2): $(OBJS2)
	$(CC) -o $@ $(OBJS2)
	$(STRIP) --strip-all $@
endif

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)
ifeq ($(CONFIG_IPV6),y)
	rm -f $(OBJS2) $(TARGET2) $(OBJS2:%.o=.%.depend)
endif

install:
	$(ROMFSINST) /bin/$(TARGET)
ifeq ($(CONFIG_IPV6),y)
	$(ROMFSINST) $(TARGET2) /bin/$(TARGET2)
endif

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
