PKG_NAME := gmp
PKG_BASE := 6.1.0
PKG_PATCH :=
PKG_VERSION := $(PKG_BASE)$(PKG_PATCH)
PKG_SOURCE := $(wildcard $(PKG_NAME)-$(PKG_VERSION).*)

$(if $(PKG_SOURCE),,$(error $(PKG_NAME)-$(PKG_VERSION) not found))
PKG_BUILD_DIR ?= $(PKG_NAME)$(if $(PKG_VERSION),-$(PKG_VERSION))

TARGET_PLATFORM := mips-linux
TARGET_CROSS := $(CROSS_COMPILE)
TARGET_CC := $(TARGET_CROSS)gcc
TARGET_LD := $(TARGET_CROSS)ld
TARGET_LDFLAGS :=
INSTALLDIR := $(DIR_ROMFS)

GMP_DISABLE :=
GMP_ENABLE := static=no

GMP_OPTIONS := \
	CFLAGS="-Os -I$(STAGING_DIR)/usr/include" \
	$(if $(strip $(TARGET_CPPFLAGS)),CPPFLAGS=$(TARGET_CPPFLAGS)) \
	$(if $(strip $(TARGET_LDFLAGS)),LDFLAGS=$(TARGET_LDFLAGS)) \
	$(if $(strip $(GMP_DISABLE)),$(addprefix --disable-,$(GMP_DISABLE))) \
	$(if $(strip $(GMP_ENABLE)),$(addprefix --enable-,$(GMP_ENABLE)))

all: depend
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" LD="$(TARGET_LD)" \
		AR="$(TARGET_CROSS)ar r" \
		RANLIB="$(TARGET_CROSS)ranlib" \
		all
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) install

depend:
	@if [ ! -d $(PKG_BUILD_DIR) -a -f $(PKG_SOURCE) ]; then \
		tar xaf $(PKG_SOURCE); \
	fi; \
	pushd $(PKG_BUILD_DIR); \
	if [ ! -f config_done ]; then \
		./configure --host=$(TARGET_PLATFORM) \
			--prefix=$(STAGING_DIR) \
			$(strip $(GMP_OPTIONS)) && touch config_done; \
	fi; \
	popd

install:
ifneq ($(STAGING_DIR),$(INSTALLDIR))
	@[ ! -d "$(PKG_BUILD_DIR)" ] || { \
		pushd $(PKG_BUILD_DIR); \
		install -d $(INSTALLDIR)/usr/lib; \
		tar cf - --transform 's|^.*/||x' $$(find -name "*.so*") | (cd $(INSTALLDIR)/usr/lib && tar xBf -); \
		find -type f -name "*.so*" | (read name && $(STRIP) $(INSTALLDIR)/usr/lib/$${name##.*/}); \
		popd; \
	}
endif

clean:
	[ ! -f "$(PKG_BUILD_DIR)/Makefile" ] || $(MAKE) -C $(PKG_BUILD_DIR) $@


.PHONY: all install clean depend
