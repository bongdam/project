PKG_NAME := openssl
PKG_BASE := 1.0.2
PKG_PATCH := u
PKG_VERSION := $(PKG_BASE)$(PKG_PATCH)
PKG_SOURCE := $(wildcard $(PKG_NAME)-$(PKG_VERSION).*)

$(if $(PKG_SOURCE),,$(error $(PKG_NAME)-$(PKG_VERSION) not found))
PKG_BUILD_DIR ?= $(PKG_NAME)$(if $(PKG_VERSION),-$(PKG_VERSION))

$(eval $(if $(CROSS_COMPILE),CC=gcc))
TARGET_PLATFORM := linux-generic32
TARGET_CROSS := $(CROSS_COMPILE)
TARGET_CC := $(TARGET_CROSS)gcc
TARGET_ASFLAGS :=
INSTALLDIR := $(DIR_ROMFS)

OPENSSL_NO_CIPHERS := no-idea no-md2 no-mdc2 no-rc5 no-sha0 no-camellia no-krb5 no-static-engine no-ec2m no-ssl3 no-perlasm
OPENSSL_OPTIONS := shared no-err no-hw no-sse2 no-ssl2 no-zlib no-zlib-dynamic

all: depend
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		ASFLAGS="$(TARGET_ASFLAGS) -I$(PKG_BUILD_DIR)/crypto -c" \
		AR="$(TARGET_CROSS)ar r" \
		RANLIB="$(TARGET_CROSS)ranlib" \
		$(OPENSSL_MAKEFLAGS) \
		all
ifneq ($(strip $(STAGING_DIR)),)
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		INSTALL_PREFIX="$(STAGING_DIR)" \
		$(OPENSSL_MAKEFLAGS) \
		install_sw
endif

depend:
	@if [ ! -d $(PKG_BUILD_DIR) -a -f $(PKG_SOURCE) ]; then \
		tar xaf $(PKG_SOURCE); \
	fi; \
	pushd $(PKG_BUILD_DIR); \
	if [ ! -f config_done ]; then \
		./Configure $(TARGET_PLATFORM) \
			--prefix=/usr \
			--openssldir=/etc/ssl \
			$(TARGET_CPPFLAGS) $(TARGET_LDFLAGS) \
			-DOPENSSL_SMALL_FOOTPRINT \
			$(OPENSSL_NO_CIPHERS) \
			$(OPENSSL_OPTIONS) && touch config_done; \
	fi; \
	popd
	+$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		MAKEDEPPROG="$(TARGET_CROSS)gcc" \
		$(OPENSSL_MAKEFLAGS) \
		depend

install:
ifneq ($(STAGING_DIR),$(INSTALLDIR))
	@install -d $(INSTALLDIR)/lib
	@[ ! -d "$(PKG_BUILD_DIR)" ] || { \
		(cd $(PKG_BUILD_DIR) && tar cf - $$(find . -maxdepth 1 -name "*.so*")) | (cd $(INSTALLDIR)/lib && tar xBf -); \
	}
endif

clean:
	[ ! -f "$(PKG_BUILD_DIR)/Makefile" ] || $(MAKE) -C $(PKG_BUILD_DIR) $@


dirname:
	@echo $(PKG_BUILD_DIR)

.PHONY: all install clean dirname
