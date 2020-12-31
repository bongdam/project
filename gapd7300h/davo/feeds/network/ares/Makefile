#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ares
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/ares/Default
  TITLE:=LGU+ DNS program
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/ares/Default/description
 LG U+ DNS program
endef

define Package/ares
$(call Package/ares/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
endef

define Package/ares/description
$(call Package/ares/Default/description)
 This package provides DNS querying library and program
endef

define Build/Configure
	true
endef

TARGET_CFLAGS += \
	-g -O2 -fomit-frame-pointer -Wall \
	-DDVLOG_MARK_USER=\\\"[U]\\\" \
	-DLGDACOM_PROVIS \
	-fPIC

MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS)"

define Build/InstallDev
	mkdir -p $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/ares.h $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libares.so $(1)/usr/lib
endef

define Package/ares/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/aprovis $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libares.so $(1)/usr/lib
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
