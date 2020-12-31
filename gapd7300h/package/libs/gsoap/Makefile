#
# Copyright (C) 2006-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gsoap
PKG_VERSION:=2.8
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_LICENSE:=GPL
PKG_LICENSE_FILES:=COPYING

PKG_FIXUP:=autoreconf
#PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

CONFIGURE_ARGS += \
	ac_cv_func_malloc_0_nonnull=yes

define Package/gsoap/Default
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=gSOAP library
  URL:=https://www.genivia.com/products.html
endef

define Package/gsoap/description
 This package contains a library for SOAP implementation.
endef

define Package/gsoap
$(call Package/gsoap/Default)
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=gSOAP library
  DEPENDS:=+libopenssl +ares
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/gsoap/src 
	$(MAKE) -C $(PKG_BUILD_DIR)/gsoap/wsdl
	$(MAKE) -C $(PKG_BUILD_DIR)/gsoap
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/gsoap/cwmp_define.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/gsoap/stdsoap2.h $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/gsoap/*.a $(1)/usr/lib
endef

$(eval $(call BuildPackage,gsoap))
