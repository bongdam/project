include $(TOPDIR)/rules.mk

PKG_NAME:=lgconf_firewalld
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk


define Package/$(PKG_NAME)/Default
  TITLE:=LG_Config_Firewall_Daemon
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/$(PKG_NAME)/Default/description
 Healthcheck
endef


define Package/$(PKG_NAME)
$(call Package/$(PKG_NAME)/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+libytool +libdvuci +liblgap_pub +liblgap 
endef


define Package/$(PKG_NAME)/description
$(call Package/$(PKG_NAME)/Default/description)
 Healthcheck
endef

define Build/Configure
endef

define Build/InstallDev
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/$(PKG_NAME) $(1)/usr/sbin
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
