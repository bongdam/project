include $(TOPDIR)/rules.mk

PKG_NAME:=dvlog
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/dvlog
  TITLE:=Davolink logger
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=System
  DEPENDS:=+libubus +libubox +libblobmsg-json +libuci +dvktrace +librt
endef

define Package/libdvlog
  TITLE:=C Library for Davolink logger
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Libraries
  DEPENDS:=+libubus +libubox +libblobmsg-json
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += -lubus -lubox -lblobmsg_json

define Build/Configure
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/dvlog_cmd.h $(1)/usr/include/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/dvlog_msg.h $(1)/usr/include/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/libdvlog.so $(1)/usr/lib/
endef

define Package/dvlog/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dvlog $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dvlogger $(1)/usr/sbin
	$(INSTALL_BIN) ./files/dvlog.init $(1)/etc/init.d/dvlog
	$(INSTALL_DATA) ./files/dvlog.config $(1)/etc/config/dvlog
endef

define Package/libdvlog/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/libdvlog.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,dvlog))
$(eval $(call BuildPackage,libdvlog))
