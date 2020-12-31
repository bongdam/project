include $(TOPDIR)/rules.mk
include $(TOPDIR)/include/nls.mk

PKG_NAME:=libgsoap
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/libgsoap
  TITLE:=libgsoap(2.7)
  SUBMENU:=Libraries
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  DEPENDS:=+ares +libopenssl
endef

define Build/Configure
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/soapcpp2/stdsoap2.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/soapcpp2/cwmp_define.h $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/soapcpp2/libgsoapssl.so $(1)/usr/lib/
endef

define Package/libgsoap/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/soapcpp2/libgsoapssl.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libgsoap))
