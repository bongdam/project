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

ifdef CONFIG_RTL_AP_PACKAGE
CONFIG_RTL_AP = CONFIG_RTL_AP_PACKAGE
endif

ifdef CONFIG_RTL_AP
AP=1
SKUTAG=ap
else
GW=1
SKUTAG=gw
endif

#------------------------------------------------------------------------------
#ifndef COMMON_CFLAGS
#$(error COMMON_CFLAGS is not defined)
#endif

#ifndef APMIB_SHARED
#$(error APMIB_SHARED is not defined)
#endif

#ifndef APMIB_LIB
#$(error APMIB_LIB is not defined)
#endif

ifeq ($(APMIB_SHARED),1)
ifneq ($(CONFIG_SYSVIPC), y)
$(error You have to turn on the kernel option "System V IPC" for shared APMIB)
endif
endif

#------------------------------------------------------------------------------
.SUFFIXES:
.SUFFIXES: .o .c
.PHONY: clean all depend

LDFLAGS =  -g
CFLAGS = -Os -pipe
DEPEND = ./.depend


#------------------------------------------------------------------------------
# EXTRA_CFLAGS
#------------------------------------------------------------------------------
EXTRA_CFLAGS =

#------------------------------------------------------------------------------
# CFLAGS
#------------------------------------------------------------------------------
DEBUG	= -g -Wall
IFLAGS 	= -I.
CFLAGS += $(COMMON_CFLAGS) $(EXTRA_CFLAGS)

vpath %.c
vpath %.c ./nvram_mib
CFLAGS += -I$(CPKG_USER)/include

ifeq ($(strip $(CONFIG_NVRAM_APMIB)),y)
SOURCES = nvram_mib.c nvram_tblop.c nvram_xfer.c nvram_mibtbl.c
ifeq ($(strip $(CONFIG_NVRAM_APMIB_HIST)),y)
SOURCES += nvram_mib_set_hist.c
endif
autogen-srcs = nvram_mibtbl.c
CFLAGS += -I./nvram_mib
ld-flags = -L$(CPKG_USER)/libytool -lytool -L$(CPKG_USER)/nvram -lnvram
else
SOURCES = apmib.c mibtbl.c
autogen-srcs =
ld-flags =
endif

ifeq ($(CONFIG_APP_RTK_VOIP),y)
SOURCES += $(VOIP_APP)/flash/voip_flash.c $(VOIP_APP)/flash/voip_flash_mib.c \
	$(VOIP_APP)/flash/voip_flash_server.c $(VOIP_APP)/flash/voip_flash_client.c \
	$(VOIP_APP)/flash/voip_flash_tool.c $(VOIP_APP)/voip_manager/voip_manager.c
endif

OBJS = $(SOURCES:.c=.o)

#------------------------------------------------------------------------------
# targets
#------------------------------------------------------------------------------
all: depend $(APMIB_LIB)

ifeq ($(APMIB_SHARED),1)
$(APMIB_LIB): $(autogen-srcs) $(OBJS)
	$(CC) -s -shared -o $@ $(OBJS)
else
$(APMIB_LIB): $(OBJS)
	$(AR) rcs $(APMIB_LIB) $(OBJS) $(ld-flags);
endif

ifneq ($(autogen-srcs),)
nvram_genmib: nvram_mib_c_struct.c apmib.h mibtbl.h
	gcc -o $@ $(DEBUG) $(CFLAGS) $(IFLAGS) $<
	chmod 755 $@

$(autogen-srcs): nvram_genmib
	@./$< 1> $@
endif

clean:
	rm -f $(DEPEND) $(OBJS) *.so *.a *.o $(autogen-srcs) nvram_genmib

depend: $(SOURCES)
	if [ ! -e $(DEPEND) ]; then \
		$(CPP) $(DEBUG) $(CFLAGS) $(IFLAGS) -MM $^ > $(DEPEND); \
	fi

-include $(DEPEND)

ifeq ($(APMIB_SHARED),1)
.c.o:
	$(CC) -c -o $@ -fpic $(DEBUG) $(CFLAGS) $(IFLAGS) $<
else
.c.o:
	${CC} -c -o $@ $(DEBUG) $(CFLAGS) $(IFLAGS) $<
endif

APMIB_FLAGS = $(filter -D%, $(filter-out $(CDEFS), $(CFLAGS) $(IFLAGS) $(COMMON_SYSFLAG)))

apmib_defs: $(DIR_LINUX)/.config $(DIR_USERS)/.config
	@echo "// This is a generated file, don't edit" > .$@.h;
	@echo "#ifndef __APMIBDEFS_H_" >> .$@.h;
	@echo -e "#define __APMIBDEFS_H_\n" >> .$@.h;
	@for p in $(APMIB_FLAGS) ; do		\
	v0=$${p/-D/'#define '};			\
	echo $${v0/'='/' '} >> .$@.h;		\
	done;					\
	echo -e "\n#endif" >> .$@.h;		\
	if [ -e $@.h ]; then			\
		diff .$@.h $@.h > .diff_apmib_defs.h;	\
		if [ -s .diff_apmib_defs.h ]; then	\
			mv .$@.h $@.h;			\
		else					\
			rm .$@.h;			\
		fi;					\
		rm .diff_apmib_defs.h;			\
	else					\
		mv .$@.h $@.h;			\
	fi;
