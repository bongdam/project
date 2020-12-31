include $(TOPDIR)/rules.mk

PKG_NAME:=common_web
PKG_VERSION:=0.0.1-20161022
PKG_RELEASE=$(PKG_SOURCE_VERSION)
PKG_MAINTAINER:=take99 <take99@davolink.co.kr>
PKG_LICENSE:=ISC

include $(INCLUDE_DIR)/package.mk

define Package/common_web/default
  SUBMENU:=WEB UI
  TITLE:=Common Webpage for package creation
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
endef

define Package/common_web
  $(Package/common_web/default)
endef

define Package/common_web/description
	A web page used for illustrating package creation
endef

define Package/common_web/install
	$(INSTALL_DIR) $(1)/davolink/www
	$(CP) ./files/web_src/* $(1)/davolink/www
#	$(INSTALL_DIR) $(1)/etc/opkg
#	$(INSTALL_DATA) ./files/customfeeds.conf $(1)/etc/opkg/customfeeds.conf.bak
#	$(INSTALL_DIR) $(1)/root
#	$(INSTALL_DATA) ./files/opkg.sh.bak $(1)/root/opkg.sh.bak
endef

define Build/Compile
	true
endef

define Package/common_web/postinst
#!/bin/sh
echo "Davo package Install"
chmod 775 -R /davolink
chown nobody:root -R /davolink
chmod 775 -R /root/opkg.sh
iptables -I INPUT -j ACCEPT
endef

define Package/common_web/prerm
#!/bin/sh
echo "Davo package remove."
endef

$(eval $(call BuildPackage,common_web))
