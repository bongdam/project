
include $(TOPDIR)/rules.mk

PKG_NAME:=dhcpr
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/dhcpr/Default
	TITLE:=DHCP relay agent
	URL:=http://www.davolink.co.kr
	SUBMENU:=Network
endef

define Package/dhcpr/Default/description
	DHCP relay agent and DHCP server prober
endef

ifeq ($(CONFIG_COMPANY_LGU), y)
define Package/dhcpr
	$(call Package/dhcpr/Default)
	SECTION:=DAVOLINK
	CATEGORY:=DAVOLINK Proprietary software
	TITLE:=Davolink packages
	DEPENDS:=+dvmgmt +libuci
	DEPENDS+= +liblgap +libytool
endef
else
define Package/dhcpr
	$(call Package/dhcpr/Default)
	SECTION:=DAVOLINK
	CATEGORY:=DAVOLINK Proprietary software
	TITLE:=Davolink packages
	DEPENDS:=+dvmgmt +libuci
endef
endif

define Package/dhcpr/description
	$(call Package/dhcpr/Default/description)
	This package provides relaying and probing for DHCP
endef

define Build/Configure
	true
endef

ifeq ($(CONFIG_COMPANY_LGU), y)
define Package/dhcpr/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(CP) $(PKG_INSTALL_DIR)/* $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/$(PKG_NAME).init $(1)/etc/init.d/$(PKG_NAME)
endef
else
define Package/dhcpr/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/dhcpr $(1)/usr/sbin
#	(cd $(1)/usr/sbin && ln -s dhcpr dhcprobe)
	$(INSTALL_BIN) ./files/$(PKG_NAME).init $(1)/etc/init.d/$(PKG_NAME)
endef
endif


$(eval $(call BuildPackage,dhcpr))
