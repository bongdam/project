PKG_NAME := strongswan
PKG_BASE := 5.4.0
PKG_PATCH :=
PKG_VERSION := $(PKG_BASE)$(PKG_PATCH)
PKG_SOURCE := $(wildcard $(PKG_NAME)-$(PKG_VERSION).*)

$(if $(PKG_SOURCE),,$(error $(PKG_NAME)-$(PKG_VERSION) not found))
PKG_BUILD_DIR ?= $(PKG_NAME)$(if $(PKG_VERSION),-$(PKG_VERSION))

TARGET_PLATFORM := mips-linux
TARGET_CROSS := $(CROSS_COMPILE)
TARGET_CC := $(TARGET_CROSS)gcc
TARGET_LD := $(TARGET_CROSS)ld
TARGET_LDFLAGS := -L$(STAGING_DIR)/usr/lib
INSTALLDIR := $(DIR_ROMFS)

SSWAN_DISABLE := cmac constraints dnskey fips-prf load-warning pkcs12 pkcs7 pkcs8 pki rc2 resolve revocation scepclient
SSWAN_ENABLE := static=no shared=yes dhcp ipseckey openssl

SSWAN_OPTIONS := \
	CFLAGS="-Os -I$(STAGING_DIR)/usr/include" \
	$(if $(strip $(TARGET_CPPFLAGS)),CPPFLAGS=$(TARGET_CPPFLAGS)) \
	$(if $(strip $(TARGET_LDFLAGS)),LDFLAGS=$(TARGET_LDFLAGS)) \
	$(if $(strip $(SSWAN_DISABLE)),$(addprefix --disable-,$(SSWAN_DISABLE))) \
	$(if $(strip $(SSWAN_ENABLE)),$(addprefix --enable-,$(SSWAN_ENABLE)))

all: depend
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" LD="$(TARGET_LD)" \
		AR="$(TARGET_CROSS)ar r" \
		RANLIB="$(TARGET_CROSS)ranlib" \
		all

depend:
	@if [ ! -d $(PKG_BUILD_DIR) -a -f $(PKG_SOURCE) ]; then \
		tar xaf $(PKG_SOURCE); \
		for file in $$(ls -A patches/ 2>/dev/null); do \
			pushd $(PKG_BUILD_DIR); \
			patch -p1 < ../patches/$$file; \
			popd; \
		done; \
	fi; \
	pushd $(PKG_BUILD_DIR); \
	if [ ! -f config_done ]; then \
		./configure --host=$(TARGET_PLATFORM) \
			--prefix=$(STAGING_DIR) \
			$(strip $(SSWAN_OPTIONS)) && touch config_done; \
	fi; \
	popd

install:
ifneq ($(STAGING_DIR),$(INSTALLDIR))
	@[ ! -d "$(PKG_BUILD_DIR)" ] || { \
		pushd $(PKG_BUILD_DIR); \
		ln -sf /var/ipsec/ipsec.conf $(INSTALLDIR)/etc/ipsec.conf; \
		ln -sf /var/ipsec/ipsec.secrets $(INSTALLDIR)/etc/ipsec.secrets; \
		ln -sf /var/ipsec/strongswan.conf $(INSTALLDIR)/etc/strongswan.conf; \
		ln -sf /var/ipsec/ipsec.d $(INSTALLDIR)/etc/ipsec.d; \
		install -D -m 755 ./src/ipsec/_ipsec $(INSTALLDIR)/usr/sbin/ipsec; \
		install -D -m 755 ./src/_updown/_updown $(INSTALLDIR)/usr/libexec/ipsec/_updown; \
		for leaf in $$(find -type f \( -name "swanctl" -o -name "charon" -o -name "starter" -o -name "stroke" -o -name "_copyright" \) -path "*/.libs/*"); do \
			install -m 755 $${leaf} $(INSTALLDIR)/usr/libexec/ipsec/$${leaf##.*/}; \
			$(STRIP) $(INSTALLDIR)/usr/libexec/ipsec/$${leaf##.*/}; \
		done; \
		install -d $(INSTALLDIR)/usr/lib/ipsec; \
		tar cf - --transform 's|^.*/||x' $$(find -name "*.so*" -path "*/.libs/*" ! -path "*/plugins/*") | (cd $(INSTALLDIR)/usr/lib/ipsec && tar xBf -); \
		install -d $(INSTALLDIR)/usr/lib/ipsec/plugins; \
		tar cf - --transform 's|^.*/||x' $$(find -name "*.so*" -path "*/plugins/*") |(cd $(INSTALLDIR)/usr/lib/ipsec/plugins && tar xBf -); \
		find $(INSTALLDIR)/usr/lib/ipsec -type f -name "*.so*" -exec $(STRIP) {} \; ; \
		popd; \
	}
endif

clean:
	[ ! -f "$(PKG_BUILD_DIR)/Makefile" ] || $(MAKE) -C $(PKG_BUILD_DIR) $@

.PHONY: all install clean depend
