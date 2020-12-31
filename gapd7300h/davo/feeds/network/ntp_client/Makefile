#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ntp_client
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/ntp_client/Default
  TITLE:=NTP CLIENT (ntp_client)
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/ntp_client/Default/description
 simple network management protocol
endef

define Package/ntp_client
$(call Package/ntp_client/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+librt +libgcrypt +libdvuci +libdvapi +libdvlog +libytool +liblgap +dvflag +libdbglog
endef

define Package/ntp_client/description
$(call Package/ntp_client/Default/description)
 This package provides ntp_client daemon
endef

define Build/Configure
endef

define Package/ntp_client/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/ntp_client $(1)/usr/sbin
	$(INSTALL_BIN) ./files/ntp_client.init $(1)/etc/init.d/ntp_client
endef

$(eval $(call BuildPackage,ntp_client))
