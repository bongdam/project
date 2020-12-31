#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=secd
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/Default
  TITLE:=security daemon using LG CNS library
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/$(PKG_NAME)/Default/description
 LG U+ security daemon
endef

define Package/$(PKG_NAME)
$(call Package/$(PKG_NAME)/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  #DEPENDS:=+libdvuci +ares +libdvapi +libytool +liblgap +libopenssl +liblgap_pub +libsecplus
  DEPENDS:=+libdvuci +ares +libsecplus +liblgap +liblgap_pub +libdbglog
endef

define Package/$(PKG_NAME)/description
$(call Package/$(PKG_NAME)/Default/description)
 This package provides security daemon using LG CNS library
endef

define Build/Configure
endef

#TARGET_CFLAGS += \
#	-O2 -fomit-frame-pointer -Wall \
#	-fPIC

#MAKE_FLAGS += \
#	CFLAGS="$(TARGET_CFLAGS)"

define Build/InstallDev
    mkdir -p $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/sec_cli.h $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libsecc.so $(1)/usr/lib
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/secd $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libsecc.so $(1)/usr/lib
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
