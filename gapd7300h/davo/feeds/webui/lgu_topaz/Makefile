#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk
include $(TOPDIR)/include/nls.mk

PKG_NAME:=lgu_topaz
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

NO_HTTPS:=1
CPATH := $(shell pwd)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/Default
  TITLE:=LGU WEB UI (TOPAZ)
  URL:=http://www.davolink.co.kr
  SUBMENU:=WEB UI
endef

define Package/$(PKG_NAME)/Default/description
 LG U+ AP WEB UI
endef

define Package/$(PKG_NAME)
$(call Package/$(PKG_NAME)/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+dvmgmt +libdvuci +libdvapi +libytool +liblgap +liblgap_pub +libopenssl +libcaptcha +libdvlog +libiconv-full
endef

EXTRA_CPPFLAGS+=-I$(ICONV_PREFIX)/include

define Package/$(PKG_NAME)/description
$(call Package/$(PKG_NAME)/Default/description)
 This package provides LGU WEB UI Topaz
endef

define Build/Configure
endef


define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/$(PKG_NAME) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/www
ifeq ($(NO_HTTPS),)
	$(CP) -a $(PKG_BUILD_DIR)/cert.pem $(1)/etc/cert.pem
endif
	rm -f $(1)/www/*
	$(CP) -rf $(PKG_BUILD_DIR)/www/* $(1)/www 
	$(CP) $(PKG_BUILD_DIR)/httpd.conf $(1)/etc/
	ln -sf /tmp/img $(1)/www/img 
	rm -rf $(1)/www/mobile/*
	rm -f $(1)/www/@h_*
	$(INSTALL_BIN) ./files/lgu_topaz.init $(1)/etc/init.d/lgu_topaz
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
