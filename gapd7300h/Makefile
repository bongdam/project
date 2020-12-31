# Makefile for OpenWrt
#
# Copyright (C) 2007 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

TOPDIR:=${CURDIR}
LC_ALL:=C
LANG:=C
export TOPDIR LC_ALL LANG

PROFILE:=$(patsubst CURRENT_PROFILE_%,%,$(wildcard CURRENT_PROFILE_*))
export PROFILE

# DAVO modified
# ipq4019 2x2
# ipq806x 4x4
#QCA_PROFILE?=ipq806x
QCA_PROFILE?=ipq4019
export QCA_PROFILE
ifeq ($(QCA_PROFILE), ipq4019)
EXTRA_CFLAGS += -DIPQ4019
else
EXTRA_CFLAGS += -DIPQ806X
endif
export EXTRA_CFLAGS
empty:=
space:= $(empty) $(empty)
$(if $(findstring $(space),$(TOPDIR)),$(error ERROR: The path to the OpenWrt directory must not include any spaces))

world:

include $(TOPDIR)/include/host.mk
include $(TOPDIR)/include/davo.mk

ifeq ($(PROFILE),gapd7300)
DEF_LOCAL:=-DBOARD_GAPD7300 #-DRTL_RST_GPIO_EXT
DAVO_DEF += $(DEF_LOCAL)
DAVO_DEF_KERNEL += $(DEF_LOCAL)
BOARD_GAPD7300=1
export BOARD_GAPD7300 DAVO_DEF DAVO_DEF_KERNEL
else ifeq ($(PROFILE),gapd7200)
DEF_LOCAL:=-DBOARD_GAPD7200
DAVO_DEF += $(DEF_LOCAL)
DAVO_DEF_KERNEL += $(DEF_LOCAL)
BOARD_GAPD7200=1
export BOARD_GAPD7200 DAVO_DEF DAVO_DEF_KERNEL
else
DEF_LOCAL:=-DBOARD_GAPD7300 #-DRTL_RST_GPIO_EXT
DAVO_DEF += $(DEF_LOCAL)
DAVO_DEF_KERNEL += $(DEF_LOCAL)
BOARD_GAPD7300=1
export BOARD_GAPD7300 DAVO_DEF DAVO_DEF_KERNEL
endif

ifneq ($(OPENWRT_BUILD),1)
  _SINGLE=export MAKEFLAGS=$(space);

  override OPENWRT_BUILD=1
  export OPENWRT_BUILD
  GREP_OPTIONS=
  export GREP_OPTIONS
  include $(TOPDIR)/include/debug.mk
  include $(TOPDIR)/include/depends.mk
  include $(TOPDIR)/include/toplevel.mk
else
  include rules.mk
  include $(INCLUDE_DIR)/depends.mk
  include $(INCLUDE_DIR)/subdir.mk
  include target/Makefile
  include package/Makefile
  include tools/Makefile
  include toolchain/Makefile

ifeq ($(findstring s,$(OPENWRT_VERBOSE)),)
OUTPUT_FD=8
else
OUTPUT_FD=1
endif

$(toolchain/stamp-install): $(tools/stamp-install)
$(target/stamp-compile): $(toolchain/stamp-install) $(tools/stamp-install) $(BUILD_DIR)/.prepared
$(package/stamp-compile): $(target/stamp-compile) $(package/stamp-cleanup)
$(package/stamp-install): $(package/stamp-compile)
$(target/stamp-install): $(package/stamp-compile) $(package/stamp-install)

# DAVO modified
PRODUCT_VERHEAD=$(BUILD_DIR)/dv_pkg/product_ver.h
-include $(TOPDIR)/davo/$(PROFILE)/version.mk


###
# REV get from svn
REV=$(shell export LC_ALL=C; svn info $(TOPDIR) 2>/dev/null | grep "Last Changed Rev")
REV:=r$(strip $(filter-out Last Changed Rev:, $(REV)))
###
# Convert version to decimal
MAJOR:=$(shell echo $$(( 10\#$(MAJOR) )) )
MINOR:=$(shell echo $$(( 10\#$(MINOR) )) )
BUILD:=$(shell echo $$(( 10\#$(BUILD) )) )
BUILDTIME=`date '+%Y-%m-%d %H:%M:%S'`

_profile_error:
	@echo '============================================'
	@echo PROFILE $(PROFILE) not found.; 
	@echo Use \"./profile_set gapd7200\" or \"./profile_set gapd7300\" to config profile.;
	@echo '============================================'
	@exit 1;

_profile_check:
	echo current profile $(PROFILE) >&$(OUTPUT_FD)
	@if [ ! -f "$(TOPDIR)/davo/$(PROFILE)/version.mk" ]; then \
		PROFILE=$(PROFILE) make V=s _profile_error >&$(OUTPUT_FD); \
		exit 1; \
	fi
	echo DAVO_DEF=$(DAVO_DEF)  >&$(OUTPUT_FD)
	echo DAVO_DEF_KERNEL=$(DAVO_DEF_KERNEL)  >&$(OUTPUT_FD)
	echo BOARD_GAPD7200=$(BOARD_GAPD7200)  >&$(OUTPUT_FD)
	echo BOARD_GAPD7300=$(BOARD_GAPD7300)  >&$(OUTPUT_FD)

mkver:
	@if [ -f "$(TOPDIR)/davo/$(PROFILE)/version.mk" ]; then \
		echo "#define MODEL_NAME \"$(MODEL)\"" > $(PRODUCT_VERHEAD); \
		echo "#define MAJOR_VERSION $(MAJOR)" >> $(PRODUCT_VERHEAD); \
		echo "#define MINOR_VERSION $(MINOR)" >> $(PRODUCT_VERHEAD); \
		echo "#define BUILD_VERSION $(BUILD)" >> $(PRODUCT_VERHEAD); \
		[ -z "$(VERSION_RC)" ] || echo "#define BUILD_VERSION_RC \"$(VERSION_RC)\"" >> $(PRODUCT_VERHEAD); \
		[ -z "$(UBOX_JIG)" ] || echo "#define UBOX_JIG \"$(UBOX_JIG)\"" >> $(PRODUCT_VERHEAD); \
		[ -z "$(REV)" ] || echo "#define REVISION \"$(REV)\"" >> $(PRODUCT_VERHEAD); \
		echo "#define BUILD_TIME \"$(BUILDTIME)\"" >> $(PRODUCT_VERHEAD); \
		echo "#define BUILDER \"$(shell whoami)\"" >> $(PRODUCT_VERHEAD); \
		\
		cp $(PRODUCT_VERHEAD) $(TOPDIR)/davo/buildsig_tmp; \
		date >> $(TOPDIR)/davo/buildsig_tmp; \
		echo $(REV) >> $(TOPDIR)/davo/buildsig_tmp; \
		echo "#define BUILD_SIG \"`md5sum  $(TOPDIR)/davo/buildsig_tmp | cut -d' ' -f1`\"" >> $(PRODUCT_VERHEAD); \
		\
		echo "BUILD_TIME=\"$(shell echo $(BUILDTIME) | sed -e 's/-//g' -e 's/://g' -e 's/ /_/g')\"" > $(TOPDIR)/davo/buildtime.mk; \
		echo "REVISION=\"$(REV)\"" >> $(TOPDIR)/davo/buildtime.mk; \
	fi
	-@rm $(BUILD_DIR)/dv_pkg/kernel/dvfwinfo/dvfwinfo_main.o
	-@touch $(BUILD_DIR)/dv_pkg/kernel/dvfwinfo/dvfwinfo_main.c
	-@rm $(BUILD_DIR)/dv_pkg/dvmgmt/cmdtbl/cmd_sys.o
	-@touch $(BUILD_DIR)/dv_pkg/dvbox/sanity_check.c
	-@touch $(BUILD_DIR)/dv_pkg/dvbox/set_passwd.c
	-@touch $(BUILD_DIR)/dv_pkg/lgconf_firewalld/lgconf_firewalld.c
	-@rm $(BUILD_DIR)/dv_pkg/sys_boot/.built
	-@touch $(BUILD_DIR)/dropbear-2017.75/common-session.c
printdb:
	@true

prepare: $(target/stamp-compile)

clean_kernel:
ifdef CONFIG_EXTERNAL_KERNEL_TREE
	make target/linux/clean
else
	@true
endif

clean: FORCE clean_kernel
	#rm -rf $(BUILD_DIR) $(STAGING_DIR) $(BIN_DIR) $(BUILD_LOG_DIR)
	# DAVO modified
	$(_SINGLE)$(SUBMAKE) target/linux/clean
	$(_SINGLE)$(SUBMAKE) package/clean
	rm -rf $(STAGING_DIR) $(BUILD_LOG_DIR)

dirclean: clean
	rm -rf $(STAGING_DIR_HOST) $(TOOLCHAIN_DIR) $(BUILD_DIR_HOST) $(BUILD_DIR_TOOLCHAIN)
	rm -rf $(TMP_DIR)

ifndef DUMP_TARGET_DB
$(BUILD_DIR)/.prepared: Makefile
	@mkdir -p $$(dirname $@)
	@touch $@

tmp/.prereq_packages: .config
	unset ERROR; \
	for package in $(sort $(prereq-y) $(prereq-m)); do \
		$(_SINGLE)$(NO_TRACE_MAKE) -s -r -C package/$$package prereq || ERROR=1; \
	done; \
	if [ -n "$$ERROR" ]; then \
		echo "Package prerequisite check failed."; \
		false; \
	fi
	touch $@
endif

# check prerequisites before starting to build
prereq: $(target/stamp-prereq) tmp/.prereq_packages
	@if [ ! -f "$(INCLUDE_DIR)/site/$(ARCH)" ]; then \
		echo 'ERROR: Missing site config for architecture "$(ARCH)" !'; \
		echo '       The missing file will cause configure scripts to fail during compilation.'; \
		echo '       Please provide a "$(INCLUDE_DIR)/site/$(ARCH)" file and restart the build.'; \
		exit 1; \
	fi

prepare: .config $(tools/stamp-install) $(toolchain/stamp-install)
world: _profile_check mkver prepare $(target/stamp-compile) $(package/stamp-compile) $(package/stamp-install) $(target/stamp-install) FORCE
	$(_SINGLE)$(SUBMAKE) -r package/index

.PHONY: clean dirclean prereq prepare world package/symlinks package/symlinks-install package/symlinks-clean mkver

endif
