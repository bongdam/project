#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=telnetd
PKG_VERSION:=1.2.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/telnetd/Default
  TITLE:=AP management (Telnetd)
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/telnetd/Default/description
  Telnet Server
endef

define Package/telnetd
$(call Package/telnetd/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+libpthread +librt +libgcrypt
endef

define Package/telnetd/description
$(call Package/telnetd/Default/description)
 This package provides Telnet daemon
endef

define Build/Configure
endef

define Package/telnetd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/telnetd $(1)/usr/sbin
	$(INSTALL_BIN) ./files/telnetd.init $(1)/etc/init.d/telnet
endef

$(eval $(call BuildPackage,telnetd))
