#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tc_tool
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/tc_tool/Default
  TITLE:=TC Tool
  URL:=http://www.davolink.co.kr
  SUBMENU:=utils
endef

define Package/tc_tool/Default/description
  Web server, ubus support
endef

define Package/tc_tool
$(call Package/tc_tool/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+libpthread +librt +libjson-c +libdvuci +libytool
endef

define Package/tc_tool/description
$(call Package/tc_tool/Default/description)
 This package provides TC utils.
endef

define Build/Configure
endef

define Package/tc_tool/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/tc_tool $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/rl_tool $(1)/usr/sbin
endef

$(eval $(call BuildPackage,tc_tool))
