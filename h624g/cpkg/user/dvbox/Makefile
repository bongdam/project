CFLAGS += -s -O2 -fomit-frame-pointer -Wall -I$(SRCBASE)/udhcp_skb
LDFLAGS += -L$(SRCBASE)/libytool -lytool -L$(SRCBASE)/shared -lshared
LDFLAGS += -L$(SRCBASE)/furl -lfurl -L$(SRCBASE)/nvram -lnvram -L$(SRCBASE)/laborer -lnmpipe

TARGET = dvbox
OBJS := main.o mping.o
OBJS += wmmmap.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	$(STRIP) --strip-all $@

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	$(ROMFSINST) /bin/$(TARGET)
	$(ROMFSINST) -s $(TARGET) /bin/dvflag
	$(ROMFSINST) -s $(TARGET) /bin/md
	$(ROMFSINST) -s $(TARGET) /bin/mm
	$(ROMFSINST) -s $(TARGET) /bin/furl
	$(ROMFSINST) -s $(TARGET) /bin/phyconfig
	$(ROMFSINST) -s $(TARGET) /bin/mirror
	$(ROMFSINST) -s $(TARGET) /bin/preq
	$(ROMFSINST) -s $(TARGET) /bin/wmmmap
	$(ROMFSINST) -s $(TARGET) /bin/ub
ifeq ($(strip $(PROFILE)),GNT2100)
	$(ROMFSINST) -s $(TARGET) /bin/ont
endif
	$(ROMFSINST) -s $(TARGET) /bin/resetTrap
	$(ROMFSINST) -s $(TARGET) /bin/apscanTrap
	$(ROMFSINST) -s $(TARGET) /bin/mping

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
