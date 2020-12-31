#
# Copyright (C) 2016 davolink.co.kr
#
#

include $(TOPDIR)/rules.mk

PKG_NAME:=sys_boot
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/sys_boot/Default
  TITLE:=/etc/init.d/boot script replacement
  URL:=http://www.davolink.co.kr
  SUBMENU:=System
endef

define Package/sys_boot/Default/description
 /etc/init.d/boot script replacement
endef

define Package/sys_boot
$(call Package/sys_boot/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+libubenv +libytool +libdvuci +liblgap 
  DEPENDS+=+dvbox +liblgap_pub # include file used
endef

define Package/sys_boot/description
$(call Package/sys_boot/Default/description)
 This package replaces /etc/init.d/boot script
endef

define Build/Configure
endef

#TARGET_CFLAGS += \
	-g -O2 -fomit-frame-pointer -Wall \
	-fPIC

#MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS)"

define Package/sys_boot/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/sys_boot $(1)/usr/sbin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
