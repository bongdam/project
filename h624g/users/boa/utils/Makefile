ifeq ($(wildcard $(DIR_LINUX)/.config),)
include ../../../linux-2.6.30/.config
else
include $(DIR_LINUX)/.config
endif

ifeq ($(wildcard $(DIR_USERS)/.config),)
include ../../.config
else
include $(DIR_USERS)/.config
endif

ifdef CONFIG_RTL_8198_AP_ROOT
CONFIG_RTL_AP = CONFIG_RTL_8198_AP_ROOT
endif

ifdef CONFIG_RTL_8197D_AP
CONFIG_RTL_AP = CONFIG_RTL_8197D_AP
endif

ifdef CONFIG_RTL_AP
AP=1
SKUTAG=ap
else
GW=1
SKUTAG=gw
endif

#------------------------------------------------------------------------------
ifndef COMMON_CFLAGS
$(error COMMON_CFLAGS is not defined)
endif

ifndef APMIB_SHARED
$(error APMIB_SHARED is not defined)
endif

ifndef APMIB_LIB
$(error APMIB_LIB is not defined)
endif

#------------------------------------------------------------------------------
.SUFFIXES:
.SUFFIXES: .o .c
.PHONY: clean all depend

LDFLAGS =  -g
CFLAGS = -Os -pipe
DEPEND = ./.depend


#------------------------------------------------------------------------------
APMIB_DIR=../apmib

#------------------------------------------------------------------------------
# EXTRA_CFLAGS
#------------------------------------------------------------------------------
EXTRA_CFLAGS =

#------------------------------------------------------------------------------
# CFLAGS
#------------------------------------------------------------------------------
DEBUG	= -g -Wall
IFLAGS 	= -I. -I$(APMIB_DIR)
CFLAGS += $(COMMON_CFLAGS) $(EXTRA_CFLAGS)

#include $(DIR_USERS)/.config
ifdef CONFIG_APP_MULTIPPPOE
        CFLAGS += -DMULTI_PPPOE
endif

ifeq ($(CONFIG_APP_RTK_VOIP),y)
LDFLAGS += -lpthread
endif

TARGET = depend flash
ifeq ($(strip $(CONFIG_NVRAM_APMIB)),)
SOURCES = flash.c
FLSHOBJ = flash.o
else
SOURCES = flash_nvram.c 
FLSHOBJ = flash_nvram.o
endif
ifeq ($(CONFIG_RTL_COMAPI_CFGFILE),y)
SOURCES += comapi.c
endif
ifeq ($(strip $(CONFIG_APP_FWD)),y)
SOURCES += fwd.c
TARGET += fwd
endif
ifeq ($(strip $(CONFIG_APP_CAPWAP)),y)
SOURCES += fwupg.c ../src/utility.c
TARGET += fwupg
endif

ifeq ($(strip $(CONFIG_NVRAM_APMIB)),y)
LDFLAGS += -L$(CPKG_USER)/libytool -lytool -L$(CPKG_USER)/nvram -lnvram -L$(CPKG_USER)/shared -lshared -L../davolink -lcustom
CFLAGS += -I$(CPKG_USER)/include -I$(DIR_USERS)/iptables-1.4.4/libiptc -I../davolink
endif

#------------------------------------------------------------------------------
# targets
#------------------------------------------------------------------------------
all: $(TARGET)

#ifeq ($(CONFIG_RTL_11W_SUPPORT),y)
#CFLAGS += -DCONFIG_IEEE80211W
#endif

ifeq ($(CONFIG_RTL_COMAPI_CFGFILE),y)
flash: Makefile $(FLSHOBJ) comapi.o $(APMIB_DIR)/$(APMIB_LIB)
	$(CC) -o $@ $(FLSHOBJ) comapi.o $(LDFLAGS) -L$(APMIB_DIR) -lapmib
	$(STRIP) $@
else
flash: Makefile $(FLSHOBJ) $(APMIB_DIR)/$(APMIB_LIB)
	$(CC) -o $@ $(FLSHOBJ) $(LDFLAGS) -L$(APMIB_DIR) -lapmib
	$(STRIP) $@
endif

fwd: Makefile fwd.o
	$(CC) --static -o $@ fwd.o
	$(STRIP) $@

ifeq ($(CONFIG_APP_CAPWAP),y)
fwupg: Makefile fwupg.o ../src/utility.o $(APMIB_DIR)/$(APMIB_LIB)
	$(CC) -o $@ fwupg.o ../src/utility.o $(LDFLAGS) -L$(APMIB_DIR) -lapmib
else
fwupg:

endif

clean:
	rm -f $(DEPEND)
	rm -f *.o flash fwd fwupg

depend: $(SOURCES)
	if [ ! -e $(DEPEND) ]; then \
		$(CPP) $(DEBUG) $(CFLAGS) $(IFLAGS) -MM $^ > $(DEPEND); \
	fi

-include $(DEPEND)

.c.o:
	${CC} -c -o $@ $(DEBUG) $(CFLAGS) $(IFLAGS) $<
