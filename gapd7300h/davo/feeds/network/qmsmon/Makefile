#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk
include $(TOPDIR)/include/nls.mk

PKG_NAME:=qmsmon
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/qmsmon/Default
  TITLE:=QMS Monitoring (qmsmon)
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/qmsmon/Default/description
 QMS Monitoring
endef

define Package/qmsmon
$(call Package/qmsmon/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+librt +libgcrypt +libdvuci +libdvapi +libdvlog +libytool +liblgap +libdvcwmp +libdvneon +liblgap_pub +libopenssl
endef

define Package/qmsmon/description
$(call Package/qmsmon/Default/description)
 This package provides qmsmon daemon
endef

define Build/Configure
endef

define Package/qmsmon/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/http_msg $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/qmsmon $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/event_reporter $(1)/usr/sbin
	$(INSTALL_BIN) ./files/qmsmon.init $(1)/etc/init.d/qmsmon
	$(INSTALL_BIN) ./files/event_reporter.init $(1)/etc/init.d/event_reporter
endef

$(eval $(call BuildPackage,qmsmon))
