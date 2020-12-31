include $(TOPDIR)/rules.mk

PKG_NAME:=holepunch
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/holepunch/Default
	TITLE:= AP management (HOLEPUNCH)
	URL:=http://www.davolink.co.kr
	SUBMENU:=Network
endef

define Package/holepunch
	$(call Package/holepunch/Default)
	TITLE:=Davolink packages
	SECTION:=DAVOLINK
	CATEGORY:=DAVOLINK Proprietary software
	DEPENDS:=+libdvuci +libdvlog
endef

define Package/holepunch/Default/description
	$(call Package/holepunch/Default/description)
	Holepunch Client
endef

define Build/Configure
	true
endef

define Package/holepunch/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/holepunch $(1)/usr/sbin
	$(INSTALL_BIN) ./files/$(PKG_NAME).init $(1)/etc/init.d/$(PKG_NAME)
endef

$(eval $(call BuildPackage,holepunch))
