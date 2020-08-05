############################################################################
#
# Realtek Semiconductor Corp.
#
# Makefile -- Top level dist makefile.
#
# Tony Wu (tonywu@realtek.com)
# Oct. 12, 2008
#
export LC_ALL=C
export LANG=C.UTF-8

ifneq (.config,$(wildcard .config))
TARGET := config
#
# DIR_ROOT Used when .config not Exist
#
DIR_ROOT = $(shell pwd)
DIR_USERS = $(DIR_ROOT)/users
DIR_BZBOX = $(DIR_ROOT)/users/busybox-1.13
DIR_LINUX = $(DIR_ROOT)/linux-2.6.30
export DIR_ROOT DIR_USERS DIR_BZBOX DIR_LINUX
else

include .config

#
# variables
#
DIR_ROOT = $(shell pwd)
DIR_RSDK = $(DIR_ROOT)/$(CONFIG_RSDKDIR)

ifeq ($(CONFIG_ARCH_CPU_MIPS),y)
VAR_ARCH:= mips
CROSS_TARGET := mips-linux
CROSS_COMPILE:= msdk-linux-
else
VAR_ARCH:= rlx
CROSS_TARGET := rsdk-linux
CROSS_COMPILE := rsdk-linux-
endif
export VAR_ARCH CROSS_COMPILE CROSS_TARGET

ifeq ($(CONFIG_ARCH_CPU_EL),y)
VAR_ENDIAN := EL
else
VAR_ENDIAN := EB
endif

DIR_BOARD = $(DIR_ROOT)/target
DIR_ROMFS = $(DIR_ROOT)/target/romfs
DIR_TMPFS = $(DIR_ROOT)/target/tmpfs
DIR_IMAGE = $(DIR_ROOT)/target/image
DIR_TOOLS = $(DIR_ROOT)/target/tools
DIR_USERS = $(DIR_ROOT)/users
DIR_BZBOX = $(DIR_ROOT)/$(CONFIG_BZBOXDIR)
DIR_LINUX = $(DIR_ROOT)/$(CONFIG_LINUXDIR)

ROMFSINST = $(DIR_ROOT)/config/romfsinst

RCSCONFIG = $(DIR_ROMFS)/etc/init.d/rcS.conf

MAKE = PATH=$(DIR_RSDK)/bin:$(PATH); make
LSTRIP = PATH=$(DIR_RSDK)/bin:$(PATH); rsdk-linux-lstrip
SSTRIP = PATH=$(DIR_RSDK)/bin:$(PATH); rsdk-linux-sstrip

ifeq ($(CONFIG_ARCH_CPU_MIPS),y)
LSTRIP = PATH=$(DIR_RSDK)/bin:$(PATH); msdk-linux-lstrip
SSTRIP = PATH=$(DIR_RSDK)/bin:$(PATH); msdk-linux-sstrip
endif

export DIR_ROOT DIR_RSDK DIR_ROMFS DIR_IMAGE DIR_BOARD DIR_TMPFS
export DIR_LINUX DIR_BZBOX ROMFSINST DIR_TOOLS DIR_USERS
export RCSCONFIG

ERROR :=
ifneq ($(CONFIG_BZBOXDIR),$(wildcard $(CONFIG_BZBOXDIR)))
ERROR += '$(CONFIG_BZBOXDIR) does not exist '
endif

ifneq ($(CONFIG_LINUXDIR),$(wildcard $(CONFIG_LINUXDIR)))
ERROR += '$(CONFIG_LINUXDIR) does not exist '
endif

ifneq ($(CONFIG_RSDKDIR),$(wildcard $(CONFIG_RSDKDIR)))
ERROR += '$(CONFIG_RSDKDIR) does not exist'
endif

ifeq ($(ERROR),)
# for ramfs or MP build, rootfs must be ready before kernel
TARGET := bins romfs modules external_modules linux image
#TARGET := modules linux bins romfs image
else
TARGET := error
endif

HOST_CPU_NUM ?= $(shell cat /proc/cpuinfo | grep -c processor)
PROFILE ?= P201
STAGING_DIR := $(shell mkdir -p "$(DIR_ROOT)/staging_dir"; echo "$(DIR_ROOT)/staging_dir")
CPKG_TOP = $(DIR_ROOT)/cpkg
CPKG_MODULE = $(CPKG_TOP)/module
CPKG_USER = $(CPKG_TOP)/user
export PROFILE CPKG_TOP CPKG_MODULE CPKG_USER STAGING_DIR

define iterate_var
$(shell sed -n 's/^\s*\(\w\+\)\s*=\s*\(\w*\)\s*/\1=\2/p' $(1); sed -n 's/^\s*\(\w\+\)\s*$$/\1/p' $(1);)
endef

define export_var
$(if $(findstring =,$(1)),export $(1))
CDEFS += $(if $(filter -%,$(1)),$(1),-D$(1))
export CDEFS
endef

define export_profile
$(foreach tuple,$(call iterate_var,$(1)),$(eval $(call export_var,$(tuple))))
endef

# generate global CDEFS based on per profile
$(if $(wildcard $(DIR_ROOT)/profile/$(PROFILE)/ccopt),$(call export_profile,$(DIR_ROOT)/profile/$(PROFILE)/ccopt))
$(eval $(call export_var,-I$(STAGING_DIR)/include))
endif

all: $(TARGET)

error:
	@echo
	@echo "=== NOTICE ==="
	@echo
	@for X in $(ERROR) ; do \
		echo ERROR: $$X; \
	done
	@echo
	@echo "Please run 'make config' to reconfigure"
	@echo

#
# 0. target selection
#
.PHONY: config menuconfig
config menuconfig:
	@chmod u+x config/genconfig
	@chmod u+x config/setconfig
	@config/genconfig > Kconfig
	@config/mconf Kconfig
#	@if egrep "^CONFIG_BOARD_rtl8196eu=y" .config > /dev/null; then \
#        cp $(shell pwd)/linux-2.6.30/drivers/usb/Kconfig-otg $(shell pwd)/linux-2.6.30/drivers/usb/Kconfig; \
#    else \
#        cp $(shell pwd)/linux-2.6.30/drivers/usb/Kconfig-not-otg $(shell pwd)/linux-2.6.30/drivers/usb/Kconfig; \
#	fi
	@config/setconfig defaults
	@if egrep "^CONFIG_MCONF_LINUX=y" .config > /dev/null; then \
		if egrep "^CONFIG_BOARD_rtl8197F=y" .config > /dev/null; then \
			$(MAKE) -C $(DIR_LINUX) menuconfig VAR_ARCH=mips-ori; \
		else \
			$(MAKE) -C $(DIR_LINUX) menuconfig; \
		fi \
	fi
#	if egrep "^CONFIG_SLOT_0_8192FE=y" $(shell pwd)/linux-3.10/.config > /dev/null; then \
#        rm $(shell pwd)/linux-3.10/drivers/net/wireless/rtl8192cd; \
#		ln -s rtl8192cd_92f $(shell pwd)/linux-3.10/drivers/net/wireless/rtl8192cd; \
#    else \
#		rm $(shell pwd)/linux-3.10/drivers/net/wireless/rtl8192cd; \
#		ln -s ../../../../linux-2.6.30/drivers/net/wireless/rtl8192cd $(shell pwd)/linux-3.10/drivers/net/wireless/rtl8192cd; \
#	fi
	@if egrep "^CONFIG_MCONF_USERS=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_USERS) menuconfig; \
	fi
	@if egrep "^CONFIG_MCONF_BZBOX=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_BZBOX) menuconfig; \
	fi
	@config/setconfig final
	@config/hdrconfig $(DIR_ROOT)

#
# 1. user lib
#
#.PHONY: libs
#libs:
#	$(MAKE) -C $(DIR_USERS) lib || exit $$?

#
# 2. user app
#
.PHONY: users bins
users bins:
	if egrep "^CONFIG_BOARD_rtl8197F=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_LINUX) dep VAR_ARCH=mips-ori > /dev/null; \
	else \
		$(MAKE) -C $(DIR_LINUX) dep > /dev/null; \
	fi
	$(if $(wildcard $(CPKG_MODULE)),$(MAKE) -C $(CPKG_MODULE) staging || exit $$?)
	$(if $(wildcard $(CPKG_USER)),$(MAKE) -C $(CPKG_USER) || exit $$?)
	$(MAKE) -C $(DIR_USERS) || exit $$?
	$(if $(wildcard $(CPKG_USER)),$(MAKE) -C $(CPKG_USER) late || exit $$?)

#
#2.1 user menuconfig
#
users_menuconfig:
	$(MAKE) -C $(DIR_USERS) menuconfig;

#
# 3. romfs
#
#	[ -d $(DIR_ROMFS) ] || mkdir $(DIR_ROMFS)
.PHONY: romfs
romfs:
	$(MAKE) -C $(DIR_BOARD) romfs || exit $$?
	cp -R $(DIR_RSDK)/lib/*.so $(DIR_ROMFS)/lib
	cp -R $(DIR_RSDK)/lib/*.so.* $(DIR_ROMFS)/lib
	chmod 755 $(DIR_ROMFS)/lib/*.so
	$(if $(wildcard $(CPKG_USER)),$(MAKE) -C $(CPKG_USER) romfs || exit $$?)
	$(MAKE) -C $(DIR_USERS) romfs || exit $$?
	@if [ -d $(DIR_ROOT)/profile/$(PROFILE)/files ]; then \
		echo ".svn" > $(DIR_ROOT)/xfiles; \
		egrep "CONFIG_NVRAM_APMIB=y" $(DIR_USERS)/.config 2>/dev/null || { \
			echo -e "startup.sh\nflash\nlibapmib.so" >> $(DIR_ROOT)/xfiles; \
		}; \
		(cd $(DIR_ROOT)/profile/$(PROFILE)/files && tar cf - . -X $(DIR_ROOT)/xfiles) | (cd $(DIR_ROMFS) && tar xBf -); \
		rm $(DIR_ROOT)/xfiles; \
		[ ! -f "$(CPKG_USER)/nvram/crypt.nvram" ] || { \
			$(CPKG_USER)/nvram/crypt.nvram aes USER_PASSWORD $(DIR_ROMFS)/etc/rconf.dfl || true; \
		} \
	fi
	$(LSTRIP) $(DIR_ROMFS)

#
# 4.0 kernel modules (if any)
#
.PHONY: modules
modules:
	if egrep "^CONFIG_BOARD_rtl8197F=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_LINUX) modules VAR_ARCH=mips-ori || exit $$?; \
		$(MAKE) -C $(DIR_LINUX) modules_install INSTALL_MOD_PATH=$(DIR_ROMFS) VAR_ARCH=mips-ori || exit $$?; \
	else \
		$(MAKE) -C $(DIR_LINUX) modules || exit $$?; \
		$(MAKE) -C $(DIR_LINUX) modules_install INSTALL_MOD_PATH=$(DIR_ROMFS) || exit $$?; \
	fi

#
# 4.1 kernel image
#
.PHONY: linux
linux:
	. $(DIR_LINUX)/.config; if [ "$$CONFIG_INITRAMFS_SOURCE" != "" ]; then \
        cd $(DIR_LINUX); \
        mkdir -p $(DIR_ROMFS); \
        touch $$CONFIG_INITRAMFS_SOURCE | awk '{print $2}' || exit 1; \
        cd $(DIR_ROOT); \
	fi
	if egrep "^CONFIG_BOARD_rtl8197F=y" .config > /dev/null; then \
		$(MAKE) -j $(HOST_CPU_NUM) -C $(DIR_LINUX) VAR_ARCH=mips-ori || exit $$?; \
#		$(MAKE) -C $(DIR_USERS)/MAP-master/modules VAR_ARCH=mips-ori || exit $$?; \
	else \
		$(MAKE) -j $(HOST_CPU_NUM) -C $(DIR_LINUX) || exit $$?; \
#		$(MAKE) -C $(DIR_USERS)/MAP-master/modules || exit $$?; \
	fi
	if [ -f $(DIR_LINUX)/vmlinux ]; then \
        ln -f $(DIR_LINUX)/vmlinux $(DIR_LINUX)/linux ; \
	fi

uImage:
	if egrep "^CONFIG_BOARD_rtl8197F=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_LINUX) uImage VAR_ARCH=mips-ori; \
	else \
		$(MAKE) -C $(DIR_LINUX) uImage; \
	fi

#
#4.2 kernel menuconfig
#
linux_menuconfig:
#	@if egrep "^CONFIG_BOARD_rtl8196eu=y" .config > /dev/null; then \
#        cp $(shell pwd)/linux-2.6.30/drivers/usb/Kconfig-otg $(shell pwd)/linux-2.6.30/drivers/usb/Kconfig; \
#    else \
#        cp $(shell pwd)/linux-2.6.30/drivers/usb/Kconfig-not-otg $(shell pwd)/linux-2.6.30/drivers/usb/Kconfig; \
#	fi
	if egrep "^CONFIG_BOARD_rtl8197F=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_LINUX) menuconfig VAR_ARCH=mips-ori; \
	else \
		$(MAKE) -C $(DIR_LINUX) menuconfig; \
	fi

#
#4.3 external modules
#
.PHONY: external_modules
external_modules:
	if egrep "^CONFIG_BOARD_rtl8197F=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_LINUX) dep VAR_ARCH=mips-ori > /dev/null; \
	else \
		$(MAKE) -C $(DIR_LINUX) dep > /dev/null; \
	fi
	$(MAKE) -C $(DIR_USERS) ex_mod || exit $$?

#
# 5. image
#
.PHONY: image
image:
	[ -d $(DIR_IMAGE) ] || mkdir $(DIR_IMAGE)
	$(MAKE) -C $(DIR_BOARD) image


#
# x. short-cut to build and clean one application
#
linux-clean:
	if egrep "^CONFIG_BOARD_rtl8197F=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_LINUX) clean VAR_ARCH=mips-ori; \
	else \
		$(MAKE) -C $(DIR_LINUX) clean; \
	fi

%_build:
	$(MAKE) -C users $(@:_build=)

%-build:
	$(MAKE) -C users $(@:-build=)

%_clean:
	$(MAKE) -C users/$(@:_clean=) clean

%-clean:
	$(MAKE) -C users/$(@:-clean=) clean

#.PHONY: version
#version:
#	$(MAKE) -C $(DIR_USERS)/goahead-2.1.1/LINUX release

.PHONY: clean  distclean
clean:
	$(if $(wildcard $(CPKG_USER)),$(MAKE) -C $(CPKG_USER) clean || exit $$?)
	$(MAKE) -C $(DIR_USERS) clean
	if egrep "^CONFIG_BOARD_rtl8197F=y" .config > /dev/null; then \
		$(MAKE) -C $(DIR_LINUX) clean VAR_ARCH=mips-ori; \
#		$(MAKE) -C $(DIR_USERS)/MAP-master/modules clean VAR_ARCH=mips-ori; \
	else \
		$(MAKE) -C $(DIR_LINUX) clean; \
#		$(MAKE) -C $(DIR_USERS)/MAP-master/modules clean; \
	fi
	rm -rf $(DIR_ROMFS)
	mkdir -p $(DIR_ROMFS)
	mkdir -p $(DIR_IMAGE)
	rm -rf $(STAGING_DIR)/*

distclean:
	$(MAKE) -C $(DIR_USERS) distclean
