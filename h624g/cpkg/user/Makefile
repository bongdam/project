#include ../user/.config

include $(DIR_USERS)/.config
-include $(DIR_LINUX)/.config

TOP := $(DIR_ROOT)
SRCBASE := $(shell pwd)
INSTALLDIR := $(DIR_ROMFS)
export SRCBASE INSTALLDIR

CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
LD = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
RANLIB = $(CROSS_COMPILE)ranlib
STRIP = $(CROSS_COMPILE)strip
SSTRIP = $(CROSS_COMPILE)sstrip

export CC CXX LD AR RANLIB STRIP SSTRIP

ifneq ($(strip $(CDEFS)),)
CFLAGS := $(filter-out $(CDEFS),$(CFLAGS)) $(CDEFS)
endif
CFLAGS += $(SYSNAME_FLAGS) -I$(SRCBASE)/include

export CFLAGS

obj-$(CONFIG_LIB_YTOOL) += libytool
obj-$(CONFIG_LIB_NVRAM) += nvram
obj-$(CONFIG_LIB_SHARED) += shared
obj-y += laborer
obj-$(CONFIG_APP_RC) += rc
obj-$(CONFIG_UDHCP_SKB) += udhcp_skb
obj-$(CONFIG_APP_DHCPV6) += flex-2.5.33
obj-$(CONFIG_APP_DHCPV6) += wide-dhcpv6
obj-$(CONFIG_APP_ARPROBE) += arprobe
obj-$(CONFIG_APP_RTNETLNK) += rtnetlnk
obj-$(CONFIG_APP_MINIUPNPD) += miniupnpd-1.9
obj-$(CONFIG_DVBOX) += dvbox
obj-$(CONFIG_LIB_FURL) += furl
obj-$(CONFIG_APP_HOLEPUNCH) += holepunch
obj-$(CONFIG_APP_AUTO_REBOOT) += auto_reboot
obj-$(CONFIG_ARES) += ares
obj-$(CONFIG_MPSTAT) += mpstat
obj-$(CONFIG_ACLWRITE) += aclwrite
obj-$(CONFIG_TELNET) += telnetd
obj-$(CONFIG_APP_SWMS) += swms
obj-$(CONFIG_APP_LDAP) += ldap
obj-$(CONFIG_APP_DVQOS) += dvqos
obj-$(subst m,y,$(CONFIG_BRIDGE_NF_EBTABLES)) += ebtables
obj-$(CONFIG_APP_DVSNMP) += snmp
obj-$(CONFIG_APP_IGMPQUERIER) += igmpquerier
obj-$(CONFIG_APP_ARPDEFENDER) += arp_defender
obj-$(CONFIG_APP_WLCMD) += wlcmd
obj-y += smartreset
obj-$(CONFIG_LIB_CAPTCHA) += captcha
obj-$(CONFIG_APP_CHILD_GUARD) += child_guard
obj-y += aes-cbc
obj-y += libnetfilter
obj-y += conntrack-tools
obj-y += restricted_web
obj-y += fdns

# late target
# late-obj-$(CONFIG_XXXXXX) += xxxxxx
late-obj-$(CONFIG_APP_MINIUPNPD) += miniupnpd-1.9
late-obj-$(CONFIG_ACLWRITE) += aclwrite
late-obj-$(CONFIG_APP_DVSNMP) += snmp
late-obj-$(CONFIG_APP_HOLEPUNCH) += holepunch
late-obj-y += smartreset

obj-clean := $(foreach obj,$(obj-y) $(obj-n) $(obj-),$(obj)-clean)
obj-install := $(foreach obj,$(obj-y),$(obj)-install)
obj-late := $(foreach obj,$(late-obj-y),$(obj)-late)

# separate the libraries which need to be built first
obj-prelibs = $(filter libytool nvram shared furl captcha libnetfilter, $(obj-y))
# remaining libraries that are built next
obj-postlibs := $(filter-out $(obj-prelibs) $(late-obj-y), $(obj-y))

all: $(obj-prelibs) $(obj-postlibs)

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

$(obj-y) $(obj-n) $(obj-clean) $(obj-install) $(obj-late): dummy

.PHONY: all clean distclean mrproper install package check_kernel_config
.PHONY: conf mconf oldconf kconf kmconf config menuconfig oldconfig
.PHONY: dummy
