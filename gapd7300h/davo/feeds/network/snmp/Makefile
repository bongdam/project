#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=snmp
PKG_VERSION:=1.2.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/snmp/Default
  TITLE:=AP management (snmp)
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/snmp/Default/description
 simple network management protocol
endef

define Package/snmp
$(call Package/snmp/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+libpthread +librt +libgcrypt +libdvuci +libdvapi +libdvlog
endef

define Package/snmp/description
$(call Package/snmp/Default/description)
 This package provides snmp daemon
endef

define Build/Configure
endef

TARGET_CFLAGS += \
	-I$(BUILD_DIR)/dv_pkg/libdvapi \
	-g -O2 -fomit-frame-pointer -Wall \
	-I$(PKG_BUILD_DIR)/engine

MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS)"

define Package/snmp/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/snmp $(1)/usr/sbin
	$(INSTALL_BIN) ./files/snmp.init $(1)/etc/init.d/snmp
endef

$(eval $(call BuildPackage,snmp))
