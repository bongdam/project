PKG_NAME := libexpat
PKG_BASE := R_2_2_6
PKG_PATCH :=
PKG_VERSION := $(PKG_BASE)$(PKG_PATCH)
PKG_SOURCE := $(wildcard $(PKG_NAME)-$(PKG_VERSION).*)

$(if $(PKG_SOURCE),,$(error $(PKG_NAME)-$(PKG_VERSION) not found))
PKG_BUILD_DIR ?= $(PKG_NAME)$(if $(PKG_VERSION),-$(PKG_VERSION))/expat

TARGET_PLATFORM := mips-linux
TARGET_CROSS := $(CROSS_COMPILE)
TARGET_CC := $(TARGET_CROSS)gcc
TARGET_LDFLAGS := -L$(STAGING_DIR)/usr/lib
INSTALLDIR := $(DIR_ROMFS)

EXPAT_DISABLE :=
EXPAT_WITHOUT := xmlwf docbook

EXPAT_OPTIONS := \
	CFLAGS="-Os -I$(STAGING_DIR)/usr/include" \
	$(if $(strip $(TARGET_CPPFLAGS)),CPPFLAGS=$(TARGET_CPPFLAGS)) \
	$(if $(strip $(TARGET_LDFLAGS)),LDFLAGS=$(TARGET_LDFLAGS)) \
	$(if $(strip $(EXPAT_DISABLE)),$(addprefix --disable-,$(EXPAT_DISABLE))) \
	$(if $(strip $(EXPAT_WITHOUT)),$(addprefix --without-,$(EXPAT_WITHOUT)))

all: depend
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_CROSS)ar r" \
		RANLIB="$(TARGET_CROSS)ranlib" \
		SUBDIRS=lib \
		all
	+$(MAKE) -C $(PKG_BUILD_DIR) install

depend:
	@if [ ! -d $(PKG_BUILD_DIR) -a -f $(PKG_SOURCE) ]; then \
		tar xaf $(PKG_SOURCE); \
	fi; \
	pushd $(PKG_BUILD_DIR); \
	if [ ! -f config_done ]; then \
		[ -f "configure" ] || ./buildconf.sh && \
		./configure --host=$(TARGET_PLATFORM) \
			--prefix=$(STAGING_DIR) \
			$(EXPAT_OPTIONS) && touch config_done; \
	fi; \
	popd

install:
ifneq ($(STAGING_DIR),$(INSTALLDIR))
	@install -d $(INSTALLDIR)/lib
	@[ ! -d "$(PKG_BUILD_DIR)" ] || { \
		(cd $(PKG_BUILD_DIR)/lib/.libs && tar cf - $$(find . -maxdepth 1 -name "*.so*")) | (cd $(INSTALLDIR)/lib && tar xBf -); \
	}
endif

clean:
	[ ! -f "$(PKG_BUILD_DIR)/Makefile" ] || $(MAKE) -C $(PKG_BUILD_DIR) $@


.PHONY: all install clean depend
