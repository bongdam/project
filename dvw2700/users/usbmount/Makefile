ifeq ($(wildcard $(DIR_LINUX)/.config),)
include ../../linux-2.6.30/.config
else
include $(DIR_LINUX)/.config
endif

#include ../../linux-2.6.30/.config

ifeq ($(wildcard $(DIR_USERS)/.config),)
include ../.config
else
include $(DIR_USERS)/.config
endif

ifeq ($(CONFIG_APP_EXFAT_FUSE), y)
CFLAGS += -DCONFIG_EXFAT_FUSE
endif


CFLAGS += -Os
# samba web support
ifeq ($(CONFIG_APP_SAMBA_WEB), y)
CFLAGS += -DSAMBA_WEB_SUPPORT
endif

# UTF8 support
ifeq ($(CONFIG_NLS_UTF8),y)
CFLAGS += -DNLS_UTF8_SUPPORT
endif

MIBDIR	= $(DIR_USERS)/boa/apmib
MIBLIB	= $(MIBDIR)/libapmib.so

CFLAGS += -I$(MIBDIR)
LDLIBS += $(MIBLIB)

EXEC = usbmount 
OBJS = usbmount.o fs.o
#CC = rsdk-linux-gcc
all: $(EXEC) usbStorageAppController 

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) #-L../boa/src/LINUX -lmib

usbStorageAppController: usbStorageAppController.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o usbStorageAppController usbStorageAppController.c $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/usbStorageAppController
	$(ROMFSINST) /bin/usbmount
	#$(ROMFSINST) -p 0755 /usr/hotplug
ifeq ($(CONFIG_BOA_WEB_E8B_CH),y)
	$(ROMFSINST) -p 0755 hotplug_e8b /usr/hotplug
else
	$(ROMFSINST) -p 0755 /usr/hotplug
endif
	$(ROMFSINST) -p 0755	/bin/kill_usbStorage_apps
	$(ROMFSINST) -p 0755	/bin/up_usbStorage_apps
clean:
	-rm -f $(EXEC) *.elf *.o usbStorageAppController

