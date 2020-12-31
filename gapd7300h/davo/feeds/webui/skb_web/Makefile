include $(TOPDIR)/rules.mk

PKG_NAME:=skb_web
PKG_VERSION:=0.0.1-20161022
PKG_RELEASE=$(PKG_SOURCE_VERSION)
PKG_MAINTAINER:=take99 <take99@davolink.co.kr>
PKG_LICENSE:=ISC

include $(INCLUDE_DIR)/package.mk

define Package/skb_web/default
  SUBMENU:=WEB UI
  TITLE:=SKB Webpage for package creation
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
endef

define Package/skb_web
  $(Package/skb_web/default)
  DEPENDS:=+common_web
endef

define Package/skb_web/description
	A web page used for illustrating package creation
endef

define Package/skb_web/install
	$(INSTALL_DIR) $(1)/davolink/www
	$(CP) ./files/web_src/* $(1)/davolink/www
endef

define Build/Compile
	true
endef

define Package/skb_web/postinst
#!/bin/sh
echo "Davo package Install"
chmod 775 -R /davolink
chown nobody:root -R /davolink
endef

define Package/skb_web/prerm
#!/bin/sh
echo "Davo package remove."
endef


$(eval $(call BuildPackage,skb_web))
