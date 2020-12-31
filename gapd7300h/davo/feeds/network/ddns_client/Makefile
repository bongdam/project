#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ddns_client
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/ddns_client/Default
  TITLE:=NTP CLIENT (ddns_client)
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/ddns_client/Default/description
 simple network management protocol
endef

define Package/ddns_client
$(call Package/ddns_client/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+librt +libgcrypt +libdvuci +libdvapi +libdvlog +libytool +liblgap
endef

define Package/ddns_client/description
$(call Package/ddns_client/Default/description)
 This package provides ddns_client daemon
endef

define Build/Configure
endef

TARGET_CFLAGS += \
	-I$(BUILD_DIR)/dv_pkg/libdvapi \
	-I$(PKG_BUILD_DIR) \
	-I$(PKG_BUILD_DIR)/include \
	-g -O2 -fomit-frame-pointer -Wall

MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS)"

define Package/ddns_client/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/ddns_client $(1)/usr/sbin
	$(INSTALL_BIN) ./files/ddns_client.init $(1)/etc/init.d/ddns_client
endef

$(eval $(call BuildPackage,ddns_client))
