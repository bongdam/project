CFLAGS += -g -Os -fomit-frame-pointer -fno-strict-aliasing -Wall
CFLAGS += -DSYSLOG -DCOMBINED_BINARY
CFLAGS += -I$(SRCBASE)/include
LDFLAGS = -L$(SRCBASE)/libytool -lytool
LDFLAGS += -L$(SRCBASE)/nvram -lnvram

OPTION82 = n

EXEC1 = udhcpd
OBJS1 := utility.o arpping.o options.o clientpacket.o files.o leases.o packet.o \
	 socket.o pidfile.o serverpacket.o frontend.o script.o dhcpc.o dhcpd.o probe.o 

ifeq ($(OPTION82),y)
OBJS1 += dhcpr.o
EXEC4 = dhcpr
CFLAGS += -DOPTION82
endif

EXEC2 = udhcpc
OBJS2 =

EXEC3 = dumpleases
OBJS3 = dumpleases.o utility.o


all: $(EXEC1) $(EXEC3)

$(EXEC1): $(OBJS1)
	$(CC) -o $@ $(OBJS1) $(LDFLAGS)
	$(STRIP) --remove-section=.note --remove-section=.comment $@

$(EXEC3): $(OBJS3)
	$(CC) -o $@ $(OBJS3) $(LDFLAGS)
	$(STRIP) --strip-all $@

clean:
	rm -f $(OBJS1) $(OBJS2) $(OBJS3) $(EXEC1) $(EXEC3) $(OBJS1:%.o=.%.depend) $(OBJS2:%.o=.%.depend) $(OBJS3:%.o=.%.depend)

install: all
	$(ROMFSINST) udhcpd /bin/udhcpd
	mkdir -p $(DIR_ROMFS)/usr/share
	mkdir -p $(DIR_ROMFS)/usr/share/udhcpc
	cp ./mips-scripts/* $(DIR_ROMFS)/usr/share/udhcpc
	cp $(DIR_USERS)/script/cinit/eth1.bound $(DIR_ROMFS)/usr/share/udhcpc/eth1.bound
	cp $(DIR_USERS)/script/cinit/wlan0.bound $(DIR_ROMFS)/usr/share/udhcpc/wlan0.bound
	cp $(DIR_USERS)/script/cinit/wlan1.bound $(DIR_ROMFS)/usr/share/udhcpc/wlan1.bound
	cp $(DIR_USERS)/script/cinit/br0.bound $(DIR_ROMFS)/usr/share/udhcpc/br0.bound
	$(ROMFSINST) -s /var/udhcpc /etc/
	rm $(DIR_ROMFS)/usr/share/udhcpc/*.deconfig
	$(ROMFSINST) -s /var/udhcpc/br0.deconfig /usr/share/udhcpc/br0.deconfig
	$(ROMFSINST) -s /var/udhcpc/eth0.deconfig /usr/share/udhcpc/eth0.deconfig
	$(ROMFSINST) -s /var/udhcpc/eth1.deconfig /usr/share/udhcpc/eth1.deconfig
	$(ROMFSINST) -s /var/udhcpc/wlan0.deconfig /usr/share/udhcpc/wlan0.deconfig
	$(ROMFSINST) -s /var/udhcpc/wlan1.deconfig /usr/share/udhcpc/wlan1.deconfig
	$(ROMFSINST) -s udhcpd /bin/$(EXEC2)
	$(ROMFSINST) -s /var/udhcpd /etc
ifeq ($(OPTION82),y)
	$(ROMFSINST) -s udhcpd /bin/$(EXEC4)
endif

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS1:%.o=.%.depend)
-include $(OBJS2:%.o=.%.depend)
-include $(OBJS3:%.o=.%.depend)
endif
