#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=provision
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/provision/Default
  TITLE:=httpclient for TR069
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/provision/Default/description
 simple network management protocol
endef

define Package/provision
$(call Package/provision/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+ares +libdvneon +libytool +libopenssl +libexpat +libdvuci +libdvct
endef

define Package/provision/description
$(call Package/provision/Default/description)
 This package provides httpclient for TR069.
endef

define Build/Configure
endef

define Build/InstallDev                                                         
	mkdir -p $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/provision.h $(1)/usr/include
endef

define Package/provision/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/provision $(1)/usr/sbin
endef

$(eval $(call BuildPackage,provision))
