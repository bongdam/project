include $(TOPDIR)/rules.mk

PKG_NAME:=liblgap_pub
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/liblgap_pub
  TITLE:=utility for lg ap public function
  SUBMENU:=Libraries
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  DEPENDS:=+libytool +liblgap +libopenssl +libdvuci +swconfig +dvflag +libnl-tiny +libubenv
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += 

define Build/Configure
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/liblgap_pub.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/strtok_s.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/ifport_counter.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/dv_crypt.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/dv_rsa.h $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/liblgap_pub.so $(1)/usr/lib/
endef

define Package/liblgap_pub/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/liblgap_pub.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,liblgap_pub))
