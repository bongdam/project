#CC		= mips-uclibc-gcc
COPT		= -Os 
CFLAGS		= ${COPT} 
#STRIP		= mips-uclibc-strip
ifeq ($(wildcard $(DIR_LINUX)/.config),)
include $(DIR_ROOT)/linux-2.6.30/.config
else
include $(DIR_LINUX)/.config
endif
#include ../../linux-2.6.30/.config

ifeq ($(wildcard $(DIR_USERS)/.config),)
include ../.config
else
include $(DIR_USERS)/.config
endif

ifeq ($(wildcard $(DIR_ROOT)/.config),)
include ../../.config
else
include $(DIR_ROOT)/.config
endif

CFLAGS += $(EXTRA_CFLAGS)
ifeq ($(CONFIG_CPU_LITTLE_ENDIAN),y)
CFLAGS += -DL_ENDIAN
else
CFLAGS += -DB_ENDIAN
endif
CFLAGS += $(COMMON_CFLAGS)

TOOCHAIN = $(notdir $(CONFIG_RSDKDIR))
BTCONFIG_UTIL_LIB = libbtconfig_util_$(TOOCHAIN).so

ifeq ($(wildcard rtk_btconfig_common.c),)
SOURCES =
else
SOURCES = rtk_btconfig_common.c rtk_btconfig_common.h rtk_wlan.h
endif
OBJS = $(SOURCES:.c=.o)

all:  libbtconfig_util.so 

libbtconfig_util.so : $(BTCONFIG_UTIL_LIB)
	cp $(BTCONFIG_UTIL_LIB) libbtconfig_util.so
	
clean:
	@if [ -f rtk_btconfig_common.c ];then \
	rm -f $(BTCONFIG_UTIL_LIB) rtk_btconfig_common.o ;\
	echo "rm .o .so!" ;\
	else \
	echo "make clean!" ;\
	fi;	
	@rm -rf libbtconfig_util.so

.c.o:
	$(CC) -c -o $@ -fpic $(DEBUG) $(CFLAGS) $(LDFLAGS) $<

$(BTCONFIG_UTIL_LIB): $(OBJS)
	$(CC) -s -shared -o $@ $(OBJS)

