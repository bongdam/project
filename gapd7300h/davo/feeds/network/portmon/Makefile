#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=portmon
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/portmon/Default
  TITLE:=Port Error Count Monitiring (portmon)
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/portmon/Default/description
 simple network management protocol
endef

define Package/portmon
$(call Package/portmon/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+librt +libgcrypt +libdvuci +libdvapi +libdvlog +libytool +liblgap +swconfig +libnl-tiny
endef

define Package/portmon/description
$(call Package/portmon/Default/description)
 This package provides portmon daemon
endef

define Build/Configure
endef

define Package/portmon/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/portmon $(1)/usr/sbin
	$(INSTALL_BIN) ./files/portmon.init $(1)/etc/init.d/portmon
endef

$(eval $(call BuildPackage,portmon))
