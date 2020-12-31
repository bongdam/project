#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=dvmgmt
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/dvmgmt/Default
  TITLE:=AP management (DVMGMT)
  URL:=http://www.davolink.co.kr
  SUBMENU:=utils
endef

define Package/dvmgmt/Default/description
  Web server, ubus support
endef

define Package/dvmgmt
$(call Package/dvmgmt/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+libpthread +librt +libjson-c +libdvuci +libdvapi +kmod-dvkpoll +kmod-qca-ssdk-hnat +libdvlog +kmod-dvgpioreset +libubus +libubox +kmod-dvbrdio +libytool
endef

define Package/dvmgmt/description
$(call Package/dvmgmt/Default/description)
 This package provides WCQM daemon
endef

define Build/Configure
endef

define Package/dvmgmt/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/dvmgmt $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libdvsh.so $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/dvsh $(1)/bin/
	$(INSTALL_BIN) ./files/dvmgmt.init $(1)/etc/init.d/dvmgmt
endef

$(eval $(call BuildPackage,dvmgmt))
