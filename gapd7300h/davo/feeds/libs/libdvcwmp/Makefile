include $(TOPDIR)/rules.mk
include $(TOPDIR)/include/nls.mk

PKG_NAME:=libdvcwmp
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/libdvcwmp
  TITLE:=C Library for CWMP
  SUBMENU:=Libraries
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  DEPENDS:=+dvmgmt +libdvuci +libdvapi +libdvlog +liblgap_pub +libiconv-full +libubenv +iwinfo
endef

define Build/Configure
endef

EXTRA_CPPFLAGS+=-I$(ICONV_PREFIX)/include

define Build/InstallDev
	mkdir -p $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/libdvcwmp.h $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libdvcwmp.so $(1)/usr/lib/
endef

define Package/libdvcwmp/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libdvcwmp.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libdvcwmp))
