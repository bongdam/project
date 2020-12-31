include $(TOPDIR)/rules.mk

PKG_NAME:=timed_acl
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  TITLE:=Time limited ACL rule manager
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Network
  DEPENDS:=+libytool +libdvuci 
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

#TARGET_LDFLAGS += -lubus -lubox -lblobmsg_json

define Build/Configure
endef

define Build/InstallDev
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
