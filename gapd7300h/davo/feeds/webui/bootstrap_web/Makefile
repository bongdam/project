include $(TOPDIR)/rules.mk

PKG_NAME:=bootstrap_web
PKG_VERSION:=0.0.1-20161022
PKG_RELEASE=$(PKG_SOURCE_VERSION)
PKG_MAINTAINER:=take99 <take99@davolink.co.kr>
PKG_LICENSE:=ISC

include $(INCLUDE_DIR)/package.mk

define Package/bootstrap_web/default
  SUBMENU:=WEB UI
  TITLE:=Bootstrap Webpage for package creation
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
endef

define Package/bootstrap_web
  $(Package/bootstrap_web/default)
endef

define Package/bootstrap_web/description
	A web page used for illustrating package creation
endef

define Package/bootstrap_web/install
	$(INSTALL_DIR) $(1)/davolink/bt_ver
	$(CP) ./files/web_src/* $(1)/davolink/bt_ver
endef

define Build/Compile
	true
endef

define Package/bootstrap_web/postinst
#!/bin/sh
echo "Davo package Install"
endef

define Package/bootstrap_web/prerm
#!/bin/sh
echo "Davo package remove."
endef


$(eval $(call BuildPackage,bootstrap_web))
