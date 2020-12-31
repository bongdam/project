include $(TOPDIR)/rules.mk

PKG_NAME:=libdvubus
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/libdvubus
  TITLE:=C Library for UBUS wrapper function
  SUBMENU:=Libraries
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  DEPENDS:=+libubus +libubox +libblobmsg-json
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += -lubus -lubox -lblobmsg_json

define Build/Configure
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/dvubus.h $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libdvubus.so $(1)/usr/lib/
endef

define Package/libdvubus/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libdvubus.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libdvubus))
