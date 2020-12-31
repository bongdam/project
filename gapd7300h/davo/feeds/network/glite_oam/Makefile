#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk
include $(TOPDIR)/include/nls.mk

PKG_NAME:=glite_oam
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/glite_oam/Default
  TITLE:=GLITE OAM protocol
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/glite_oam/Default/description
 Giga-lite OAM (UB/DS) protocol
endef

define Package/glite_oam
$(call Package/glite_oam/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+libytool
endef

#EXTRA_CPPFLAGS+=-I$(ICONV_PREFIX)/include

define Package/glite_oam/description
$(call Package/glite_oam/Default/description)
 This package provides glite_oam daemon
endef

define Build/Configure
endef

TARGET_CFLAGS += \
	-g -O2 -fomit-frame-pointer -Wall

MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS)"

define Package/glite_oam/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/glite_oam $(1)/usr/sbin
	$(INSTALL_BIN) ./files/glite_oam.init $(1)/etc/init.d/glite_oam
endef

$(eval $(call BuildPackage,glite_oam))
