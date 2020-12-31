include $(TOPDIR)/rules.mk

PKG_NAME:=libdvapi
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/libdvapi
  TITLE:=C Library for Davolink API
  SUBMENU:=Libraries
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  DEPENDS:=+qca-wifi-10.4 +kmod-dvbrdio +kmod-qca-ssdk-hnat
#  DEPENDS:=+libubus +libubox +libblobmsg-json
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

#TARGET_LDFLAGS += -lubus -lubox -lblobmsg_json

define Build/Configure
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/dvapi.h $(1)/usr/include/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/snmp_trap_api.h $(1)/usr/include/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/libdvapi.so $(1)/usr/lib/
endef

define Package/libdvapi/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/libdvapi.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libdvapi))
