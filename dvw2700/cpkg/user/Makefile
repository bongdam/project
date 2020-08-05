#include ../user/.config

include $(DIR_USERS)/.config
-include $(DIR_LINUX)/.config

TOP := $(DIR_ROOT)
SRCBASE := $(shell pwd)
INSTALLDIR := $(DIR_ROMFS)
export SRCBASE INSTALLDIR

CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
LD = $(CROSS_COMPILE)ld
AR = $(CROSS_COMPILE)ar
RANLIB = $(CROSS_COMPILE)ranlib
STRIP = $(CROSS_COMPILE)strip
SSTRIP = $(CROSS_COMPILE)sstrip

export CC CXX LD AR RANLIB STRIP SSTRIP

ifneq ($(strip $(CDEFS)),)
CFLAGS := $(filter-out $(CDEFS),$(CFLAGS)) $(CDEFS) -include $(SRCBASE)/appconfig.h
endif
CFLAGS += $(SYSNAME_FLAGS) -I$(SRCBASE)/include

export CFLAGS

obj-$(CONFIG_LIB_YTOOL) += libytool
obj-$(CONFIG_LIB_NVRAM) += nvram
obj-$(CONFIG_LIB_SHARED) += shared
obj-$(CONFIG_LIB_SELECT_EVENT) += libselect_event
obj-$(CONFIG_LIB_CAPTCHA) += libcaptcha
obj-$(CONFIG_LIB_NETFILTER) += libnetfilter
obj-$(CONFIG_DVBOX) += dvbox
obj-$(CONFIG_LIB_FURL) += furl
obj-$(CONFIG_MPSTAT) += mpstat
obj-$(CONFIG_ACLWRITE) += aclwrite
obj-$(CONFIG_APP_WLCMD) += wlcmd
obj-$(CONFIG_APP_LABORER) += laborer
obj-$(CONFIG_TELNET) += telnetd
obj-$(CONFIG_UDHCPD) += udhcp
obj-$(CONFIG_TMS) += tms
obj-$(CONFIG_APP_DVQOS) += dvqos
obj-$(CONFIG_LIB_KCRYPTO_API) += libkcapi
obj-$(CONFIG_SNMP) += snmp

# late target
# late-obj-$(CONFIG_XXXXXX) += xxxxxx
late-obj-$(CONFIG_ACLWRITE) += aclwrite
late-obj-$(CONFIG_DVBOX) += dvbox
late-obj-$(CONFIG_TMS) += tms
late-obj-$(CONFIG_SNMP) += snmp

obj-clean := $(foreach obj,$(obj-y) $(obj-n) $(obj-),$(obj)-clean)
obj-install := $(foreach obj,$(obj-y),$(obj)-install)
obj-late := $(foreach obj,$(late-obj-y),$(obj)-late)

# separate the libraries which need to be built first
obj-prelibs = $(filter libytool nvram shared libkcapi furl libselect_event libcaptcha, libnetfilter, $(obj-y))
# remaining libraries that are built next
obj-postlibs := $(filter-out $(obj-prelibs) $(late-obj-y), $(obj-y))

all: appconfig $(obj-prelibs) $(obj-postlibs)

clean: $(obj-clean)

romfs: $(obj-install)

late: $(obj-late)
	@:
#
# Generic rules
#
%:
	[ ! -d $* ] || $(MAKE) -C $*

%-clean:
	[ ! -d $* ] || $(MAKE) -C $* clean

%-install:
	[ ! -d $* ] || $(MAKE) -C $* install

%-late:
	[ ! -d $* ] || $(MAKE) -C $*

appconfig: $(DIR_USERS)/.config apmib_defs
	@echo "// Automatically generated file, don't edit" > .$@.h; \
	cat $< | grep -P "^\s*([A-Z]\w*)\s*=\s*\"\w*\"" | sed 's/^\s*\([A-Z]\w*\)\s*=\s*\(\"\w*\"\)/\#define __\1__ \2/g' >> .$@.h; \
	cat $< | grep -P "^\s*([A-Z]\w*)\s*=\s*y" | sed 's/^\s*\([A-Z]\w*\)\s*=\s*\(y\)/\#define __\1__ 1/g' >> .$@.h; \
	cat $< | grep -P "^\s*([A-Z]\w*)\s*=\s*m" | sed 's/^\s*\([A-Z]\w*\)\s*=\s*\(m\)/\#define __\1_MODULE__ 1/g' >> .$@.h; \
	if [ -e $@.h ]; then			\
		diff .$@.h $@.h > .diff_$@.h;	\
		if [ -s .diff_$@.h ]; then	\
			mv .$@.h $@.h;		\
		else				\
			rm .$@.h;		\
		fi;				\
		rm .diff_$@.h;			\
	else					\
		mv .$@.h $@.h;			\
	fi;

apmib_defs:
	@$(MAKE) -C $(DIR_USERS) $@

$(obj-y) $(obj-n) $(obj-clean) $(obj-install) $(obj-late): dummy

.PHONY: all clean distclean mrproper install package check_kernel_config appconfig apmib_defs
.PHONY: conf mconf oldconf kconf kmconf config menuconfig oldconfig
.PHONY: dummy
