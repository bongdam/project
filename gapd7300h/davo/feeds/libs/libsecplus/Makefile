include $(TOPDIR)/rules.mk

PKG_NAME:=libsecplus
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/safezone_iot_20171029

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/libsecplus
  TITLE:=LG CNS module library
  SUBMENU:=Libraries
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  DEPENDS:= +kmod-pufcns +libpthread
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += 

define Build/Configure
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/secplus_ap_if.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/secplus_err_if.h $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libsecplus_gw32.so $(1)/usr/lib/
endef

define Package/libsecplus/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libsecplus_gw32.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libsecplus))
