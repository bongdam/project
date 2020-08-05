PKG_NAME := accel-pptp
PKG_BASE := 0.8.5
PKG_PATCH :=
PKG_VERSION := $(PKG_BASE)$(PKG_PATCH)
PKG_SOURCE := $(wildcard $(PKG_NAME)-$(PKG_VERSION).*)

$(if $(PKG_SOURCE),,$(error $(PKG_NAME)-$(PKG_VERSION) not found))
PKG_BUILD_DIR ?= $(PKG_NAME)$(if $(PKG_VERSION),-$(PKG_VERSION))

PKG_SUBDIRS := pptpd-1.3.3 pppd_plugin

TARGET_PLATFORM := mips-linux
TARGET_CROSS := $(CROSS_COMPILE)
TARGET_CC := $(TARGET_CROSS)gcc
TARGET_LDFLAGS :=
INSTALLDIR := $(DIR_ROMFS)
PPPD_VER=$(shell pppd_src=$$(ls -d $(DIR_USERS)/ppp-*); echo $${pppd_src\#\#*-})

CONFIGURE_DISABLE :=
CONFIGURE_WITHOUT :=
CONFIGURE_OPTIONS := \
	CFLAGS="-Os" KDIR=$(STAGING_DIR) \
	$(if $(strip $(TARGET_CPPFLAGS)),CPPFLAGS=$(TARGET_CPPFLAGS)) \
	$(if $(strip $(TARGET_LDFLAGS)),LDFLAGS=$(TARGET_LDFLAGS)) \
	$(if $(strip $(CONFIGURE_DISABLE)),$(addprefix --disable-,$(CONFIGURE_DISABLE))) \
	$(if $(strip $(CONFIGURE_WITHOUT)),$(addprefix --without-,$(CONFIGURE_WITHOUT)))

CONFIGURE_OPTIONS := $(strip $(CONFIGURE_OPTIONS))

all: depend
	@for dir in $(PKG_SUBDIRS); do $(MAKE) -C $(PKG_BUILD_DIR)/$${dir}; done
	$(MAKE) -C $(PKG_BUILD_DIR)/pppd_plugin install

# fake:
# determine pppd's version
# kernel header path
depend:
	@if [ ! -d $(PKG_BUILD_DIR) -a -f $(PKG_SOURCE) ]; then \
		tar xaf $(PKG_SOURCE); \
		for file in $$(ls -A patches/ 2>/dev/null); do \
			pushd $(PKG_BUILD_DIR); \
			patch -p1 < ../patches/$$file; \
			popd; \
		done; \
	fi; \
	if [ ! -f $(PKG_BUILD_DIR)/config_done ]; then \
		tmp=$$(mktemp); \
		echo "echo pppd version $(PPPD_VER)" >$${tmp}; \
		chmod 0755 $${tmp}; \
		for dir in $(PKG_SUBDIRS); do \
			sed -i "s|^pppd=.*|pppd=\`which $${tmp}\`|" $(PKG_BUILD_DIR)/$${dir}/configure; \
		done; \
		cat $(DIR_LINUX)/Makefile | head -n 4 >$(STAGING_DIR)/Makefile; \
		mkdir -p $(STAGING_DIR)/include && mkdir -p $(STAGING_DIR)/include/linux && touch $(STAGING_DIR)/include/linux/version.h; \
		pushd $(PKG_BUILD_DIR); \
		for dir in $(PKG_SUBDIRS); do \
			(cd $${dir} && ./configure --host=$(TARGET_PLATFORM) --prefix=$(STAGING_DIR) $(CONFIGURE_OPTIONS)); \
		done; \
		popd; \
		touch $(PKG_BUILD_DIR)/config_done; \
		rm $(STAGING_DIR)/Makefile $(STAGING_DIR)/include/linux/version.h $${tmp}; \
	fi

install:
ifneq ($(STAGING_DIR),$(INSTALLDIR))
	@install -d $(INSTALLDIR)/lib/pppd/$(PPPD_VER)
	@install -d $(INSTALLDIR)/usr/sbin
	@if [ -d "$(PKG_BUILD_DIR)/pppd_plugin/src/.libs" ]; then \
		(cd $(PKG_BUILD_DIR)/pppd_plugin/src/.libs && tar cf - $$(find . -maxdepth 1 -name "*.so*")) | (cd $(INSTALLDIR)/lib/pppd/$(PPPD_VER) && tar xBf -); \
	fi; \
	if [ -d "$(PKG_BUILD_DIR)/pptpd-1.3.3" ]; then \
		install -m 755 $(PKG_BUILD_DIR)/pptpd-1.3.3/pptpd $(INSTALLDIR)/usr/sbin; \
		install -m 755 $(PKG_BUILD_DIR)/pptpd-1.3.3/pptpctrl $(INSTALLDIR)/usr/sbin; \
	fi
endif

clean:
	@for dir in $(PKG_SUBDIRS); do \
		[ ! -d "$(PKG_BUILD_DIR)/$${dir}" ] || $(MAKE) -C $(PKG_BUILD_DIR)/$${dir} $@; \
	done

.PHONY: all install clean depend
