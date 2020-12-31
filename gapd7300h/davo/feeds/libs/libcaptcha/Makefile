include $(TOPDIR)/rules.mk

PKG_NAME:=libcaptcha
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/libcaptcha
  TITLE:=C Library for CAPTCHA IMG
  SUBMENU:=Libraries
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  DEPENDS:=
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += 

define Build/Configure
endef

define Build/InstallDev
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libcaptcha.so $(1)/usr/lib/
endef

define Package/libcaptcha/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libcaptcha.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libcaptcha))
