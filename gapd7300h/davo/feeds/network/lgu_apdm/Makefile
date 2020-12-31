#
# Copyright (C) 2016 davolink.co.kr
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk
include $(TOPDIR)/include/nls.mk

PKG_NAME:=lgu_apdm
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_MD5SUM:=973a2513d0076e34aa9da7e15ed98e1b
PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>

PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/lgu_apdm/Default
  TITLE:=APDM protocol (APDM)
  URL:=http://www.davolink.co.kr
  SUBMENU:=Network
endef

define Package/lgu_apdm/Default/description
 LG U+ AP device management protocol
endef

define Package/lgu_apdm
$(call Package/lgu_apdm/Default)
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  TITLE:=Davolink packages
  DEPENDS:=+libdvuci +libdvapi +libytool +liblgap +libopenssl +liblgap_pub +libiconv-full
endef

EXTRA_CPPFLAGS+=-I$(ICONV_PREFIX)/include

define Package/lgu_apdm/description
$(call Package/lgu_apdm/Default/description)
 This package provides LGU APDM daemon
endef

define Build/Configure
endef

TARGET_CFLAGS += \
	-g -O2 -fomit-frame-pointer -Wall \
	-DAPDM_SVR_PORT=53456

MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS)"

define Package/lgu_apdm/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/lgu_apdm_svr $(1)/usr/sbin
	ln -sf lgu_apdm_svr $(1)/usr/sbin/lgu_apdm_discover
	$(INSTALL_BIN) ./files/lgu_apdm.init $(1)/etc/init.d/lgu_apdm
endef

$(eval $(call BuildPackage,lgu_apdm))
