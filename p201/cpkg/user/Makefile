$(eval $(if $(strip $(DIR_USERS)),,DIR_USERS=$(DIR_ROOT)/user))
$(eval $(if $(strip $(DIR_LINUX)),,export DIR_LINUX=$(KERNEL_DIR)))

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
ifeq ($(findstring $(firstword $(filter -D%,$(CDEFS))),$(CFLAGS)),)
CFLAGS += $(CDEFS)
endif
ifeq ($(findstring appconfig.h, $(CFLAGS)),)
CFLAGS += -include $(SRCBASE)/appconfig.h
endif
endif
export CFLAGS

obj-$(CONFIG_LIB_NVRAM) += nvram
obj-$(CONFIG_LIB_YTOOL) += libytool
obj-$(CONFIG_LIB_SHARED) += libshared
obj-$(CONFIG_LIB_SELECT_EVENT) += libselect_event
obj-$(CONFIG_LIB_KCRYPTO_API) += libkcapi
obj-$(CONFIG_LIB_NETFILTER) += libnetfilter
obj-$(CONFIG_DVBOX) += dvbox
obj-$(CONFIG_APP_LABORER) += laborer
obj-$(CONFIG_LIB_FURL) += furl
obj-$(CONFIG_LIB_SSL) += openssl
obj-$(CONFIG_SEC_CONTAINER) += dvct
obj-$(CONFIG_ACLWRITE) += aclwrite
obj-$(CONFIG_LIB_CURL_NEW) += curl
obj-$(CONFIG_APP_VPN_SERVER) += vpn
obj-$(CONFIG_LIB_EXPAT_XML) += expat
obj-$(CONFIG_LIB_GSOAP) += gsoap
obj-$(CONFIG_APP_CWMPCLIENT) += cwmp
obj-$(CONFIG_APP_MINIUPNPD) += miniupnpd-1.9
obj-$(CONFIG_APP_REBOOT_SCHD) += reboot_schd

# late target
# late-obj-$(CONFIG_XXXXXX) += xxxxxx
late-obj-$(CONFIG_DVBOX) += dvbox
late-obj-$(CONFIG_APP_LABORER) += laborer
late-obj-$(CONFIG_ACLWRITE) += aclwrite
late-obj-$(CONFIG_APP_CWMPCLIENT) += cwmp
late-obj-$(CONFIG_APP_MINIUPNPD) += miniupnpd-1.9

obj-clean := $(foreach obj,$(obj-y) $(obj-n) $(obj-),$(obj)-clean)
obj-install := $(foreach obj,$(obj-y),$(obj)-install)
obj-late := $(foreach obj,$(late-obj-y),$(obj)-late)

# objs follow the below dependency order
depends = openssl curl expat gsoap nvram libytool libshared libselect_event libkcapi dvct furl libnetfilter
# separate the libraries which need to be built first
obj-prelibs := $(foreach dir,$(depends),$(filter $(obj-y),$(dir)))
# remaining libraries that are built next
obj-postlibs := $(filter-out $(obj-prelibs) $(late-obj-y),$(obj-y))

all: appconfig $(obj-prelibs) $(obj-postlibs)

clean: $(obj-clean)

romfs: $(obj-install)

late: $(obj-late)
	@:

appconfig: $(DIR_USERS)/.config apmib_defs
	@if [ -f "$<" ]; then \
		echo "// Automatically generated file, don't edit" > .$@.h; \
		sed -n 's/^\s*\([A-Z]\w*\)\s*=\s*\(\".*\"\)/\#define __\1__ \2/p' $< >> .$@.h; \
		sed -n 's/^\s*\([A-Z]\w*\)\s*=\s*\(y\)/\#define __\1__ 1/p' $< >> .$@.h; \
		sed -n 's/^\s*\([A-Z]\w*\)\s*=\s*\(m\)/\#define __\1_MODULE__ 1/p' $< >> .$@.h; \
		echo '#define _PATH_PASSWD "/var/passwd"' >> .$@.h; \
		if [ -e $@.h ]; then			\
			diff .$@.h $@.h >/dev/null 2>&1 && rm -f .$@.h || mv .$@.h $@.h; \
		else					\
			mv .$@.h $@.h;			\
		fi; \
	fi

apmib_defs:
	@$(MAKE) -C $(DIR_USERS) $@

#
# Generic rules
#
%:
ifeq ($(strip $(STAGING_DIR)),)
	@[ ! -d $* ] || $(MAKE) -C $*
else
	@[ ! -d $* ] || $(MAKE) -C $* && INSTALLDIR=$(strip $(STAGING_DIR)) $(MAKE) -C $* install
endif

%-clean:
	@[ ! -d $* ] || $(MAKE) -C $* clean

%-install:
	@[ ! -d $* ] || $(MAKE) -C $* install

%-late:
	@[ ! -d $* ] || $(MAKE) -C $*

%_only:
	@[ -z "$(findstring $*,$(obj-y))" ] || $(MAKE) -C $*

$(obj-y) $(obj-n) $(obj-clean) $(obj-install) $(obj-late): dummy

.PHONY: all clean distclean mrproper install package check_kernel_config appconfig apmib_defs
.PHONY: conf mconf oldconf kconf kmconf config menuconfig oldconfig
.PHONY: dummy romfs
