#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libdvneon
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/libdvneon/Default
  TITLE:=Customized NEON library
  URL:=http://www.davolink.co.kr
  SUBMENU:=Libraries
endef

define Package/libdvneon/Default/description
 Customized NEON library
endef

define Package/libdvneon
$(call Package/libdvneon/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+libopenssl +libexpat +libgsoap
endef 

define Package/libdvneon/description
$(call Package/libdvneon/Default/description)
 This package provides Customized NEON library
endef

define Build/Configure
	true
endef

TARGET_CFLAGS += \
	-g -O2 -fomit-frame-pointer -Wall \
	-fPIC

MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS)"

define Build/InstallDev
	mkdir -p $(1)/usr/include/dvneon
	$(CP) $(PKG_BUILD_DIR)/*.h $(1)/usr/include/dvneon
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/*.so $(1)/usr/lib
endef

define Package/libdvneon/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libdvneon.so $(1)/usr/lib
endef

$(eval $(call BuildPackage,$(PKG_NAME),+libopenssl))
