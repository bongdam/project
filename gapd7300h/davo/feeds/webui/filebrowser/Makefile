include $(TOPDIR)/rules.mk

PKG_NAME:=file_manager
PKG_VERSION:=0.0.1-20170215
PKG_RELEASE=$(PKG_SOURCE_VERSION)
PKG_MAINTAINER:=take99 <take99@davolink.co.kr>
PKG_LICENSE:=ISC

include $(INCLUDE_DIR)/package.mk

define Package/file_manager/default
  SUBMENU:=WEB UI
  TITLE:=Sencha Webpage for package creation
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
endef

define Package/file_manager
  $(Package/file_manager/default)
endef

define Package/file_manager/description
	A web page used for illustrating package creation
endef

define Package/file_manager/install
	$(INSTALL_DIR) $(1)/davolink/file_manager
	$(CP) ./files/web_src/* $(1)/davolink/file_manager
endef

define Build/Compile
	true
endef

define Package/file_manager/postinst
#!/bin/sh
echo "Davo package Install"
chmod 775 -R /davolink
chown nobody:root -R /davolink
endef

define Package/file_manager/prerm
#!/bin/sh
echo "Davo package remove."
endef

$(eval $(call BuildPackage,file_manager))
