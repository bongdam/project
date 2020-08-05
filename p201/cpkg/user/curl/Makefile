PKG_NAME := curl
PKG_BASE := 7.58.0
PKG_PATCH :=
PKG_VERSION := $(PKG_BASE)$(PKG_PATCH)
PKG_SOURCE := $(wildcard $(PKG_NAME)-$(PKG_VERSION).*)

$(if $(PKG_SOURCE),,$(error $(PKG_NAME)-$(PKG_VERSION) not found))
PKG_BUILD_DIR ?= $(PKG_NAME)$(if $(PKG_VERSION),-$(PKG_VERSION))

TARGET_PLATFORM := mips-linux
TARGET_CROSS := $(CROSS_COMPILE)
TARGET_CC := $(TARGET_CROSS)gcc
TARGET_LDFLAGS := -L$(STAGING_DIR)/usr/lib
INSTALLDIR := $(DIR_ROMFS)

CURL_DISABLE := file ldap ldaps rtsp dict telnet pop3 imap smb smtp gopher manual
CURL_WITHOUT := zlib gnutls polarssl mbedtls cyassl nss axtls librtmp winidn libidn2

CURL_OPTIONS := \
	CFLAGS="-Os -I$(STAGING_DIR)/usr/include" \
	$(if $(strip $(TARGET_CPPFLAGS)),CPPFLAGS=$(TARGET_CPPFLAGS)) \
	$(if $(strip $(TARGET_LDFLAGS)),LDFLAGS=$(TARGET_LDFLAGS)) \
	$(if $(strip $(CURL_DISABLE)),$(addprefix --disable-,$(CURL_DISABLE))) \
	$(if $(strip $(CURL_WITHOUT)),$(addprefix --without-,$(CURL_WITHOUT))) \
	--enable-symbol-hiding

all: depend
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_CROSS)ar r" \
		RANLIB="$(TARGET_CROSS)ranlib" \
		all
	+$(MAKE) -C $(PKG_BUILD_DIR) install

depend:
	@if [ ! -d $(PKG_BUILD_DIR) -a -f $(PKG_SOURCE) ]; then \
		tar xaf $(PKG_SOURCE); \
	fi; \
	pushd $(PKG_BUILD_DIR); \
	if [ ! -f config_done ]; then \
		./configure --host=$(TARGET_PLATFORM) \
			--prefix=$(STAGING_DIR) \
			--with-ssl=$(STAGING_DIR)/usr \
			$(CURL_OPTIONS) && touch config_done; \
	fi; \
	popd

install:
ifneq ($(STAGING_DIR),$(INSTALLDIR))
	@install -d $(INSTALLDIR)/lib
	@[ ! -d "$(PKG_BUILD_DIR)" ] || { \
		(cd $(PKG_BUILD_DIR)/lib/.libs && tar cf - $$(find . -maxdepth 1 -name "*.so*")) | (cd $(INSTALLDIR)/lib && tar xBf -); \
		install -m 755 $(PKG_BUILD_DIR)/src/.libs/curl $(INSTALLDIR)/bin; \
	}
endif

clean:
	[ ! -f "$(PKG_BUILD_DIR)/Makefile" ] || $(MAKE) -C $(PKG_BUILD_DIR) $@


.PHONY: all install clean depend
