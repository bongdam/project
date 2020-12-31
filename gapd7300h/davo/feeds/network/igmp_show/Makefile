#
# Copyright (C) 2016 davolink.co.kr
#
#

include $(TOPDIR)/rules.mk

PKG_NAME:=igmp_show
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/igmp_show/Default
  TITLE:=IGMP test application to show table and check multicast stream.
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/igmp_show/Default/description
 IGMP table show and test MC stream
endef

define Package/igmp_show
$(call Package/igmp_show/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+libytool +libdvuci
endef

define Package/igmp_show/description
$(call Package/igmp_show/Default/description)
 This package provides IGMP membership table from snoop file
endef

define Build/Configure
endef

TARGET_CFLAGS += \
	-g -O2 -fomit-frame-pointer -Wall \
	-fPIC

MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS)"

define Package/igmp_show/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/igmp_show $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/igmp_send $(1)/usr/sbin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
