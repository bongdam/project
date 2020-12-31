include $(TOPDIR)/rules.mk

PKG_NAME:=libdvuci
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

#PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/libdvuci
  TITLE:=C Library for UCI wrapper function
  SUBMENU:=Libraries
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  DEPENDS:=+libuci +libpthread
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += -luci -lpthread

define Build/Configure
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/dvuci.h $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libdvuci.so $(1)/usr/lib/
endef

define Package/libdvuci/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libdvuci.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libdvuci))
