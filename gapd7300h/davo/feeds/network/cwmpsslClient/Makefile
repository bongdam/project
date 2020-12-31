#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk
include $(TOPDIR)/include/nls.mk

PKG_NAME:=cwmpsslClient
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/cwmpsslClient/Default
  TITLE:=TR069 CWMP Client
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/cwmpsslClient/Default/description
 TR069 CWMP Client
endef

define Package/cwmpsslClient
$(call Package/cwmpsslClient/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+dvmgmt +ares +libytool +libopenssl +liblgap +liblgap_pub +provision +libgsoap +libpthread +libdvuci +libdvapi +libdvlog +libiconv-full +libdvcwmp +dvflag +libdbglog +secd
endef

define Package/cwmpsslClient/description
$(call Package/cwmpsslClient/Default/description)
 This package provides TR069 CWMP Client
endef

MAKE_FLAGS += \
	GSOAP_BIN_DIR="$(BUILD_DIR)/dv_pkg/libgsoap/soapcpp2" \
	GSOAP_SRC_DIR="$(BUILD_DIR)/dv_pkg/libgsoap/soapcpp2"

define Build/Configure
	(cd $(PKG_BUILD_DIR) && automake-1.15 --foreign --add-missing)
	$(call Build/Configure/Default,)
endef

define Package/cwmpsslClient/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/cwmpsslClient $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/tr069.init $(1)/etc/init.d/tr069
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
