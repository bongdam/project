#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=periodic_behavior
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/Default
  TITLE:=Periodic (send log, reset)
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/$(PKG_NAME)/Default/description
 LG U+ AP device management protocol
endef

define Package/$(PKG_NAME)
$(call Package/$(PKG_NAME)/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+librt +libgcrypt +libdvuci +libytool +liblgap_pub +libopenssl +libdvneon +libdvlog +liblgap +dvflag
endef

define Package/$(PKG_NAME)/description
$(call Package/$(PKG_NAME)/Default/description)
 This package provides periodic_behavior daemon
endef

define Build/Configure
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/$(PKG_NAME) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/periodic_behavior.init $(1)/etc/init.d/periodic_behavior
endef

$(eval $(call BuildPackage,periodic_behavior))
