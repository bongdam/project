include $(TOPDIR)/rules.mk

PKG_NAME:=liblgap
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define Package/liblgap
  TITLE:=utility for lg ap
  SUBMENU:=Libraries
  SECTION:=DAVOLINK
  CATEGORY:=DAVOLINK Proprietary software
  DEPENDS:=
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += 

define Build/Configure
endef

define Build/InstallDev
	mkdir -p $(1)/usr/include
	mkdir -p $(1)/usr/include/select_event
	$(CP) $(PKG_BUILD_DIR)/hanguel.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/liblgap.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/select_event/select_event.h $(1)/usr/include/select_event
	$(CP) $(PKG_BUILD_DIR)/select_event/select_event_sock.h $(1)/usr/include/select_event
	$(CP) $(PKG_BUILD_DIR)/select_event/itimer.h $(1)/usr/include/select_event
	$(CP) $(PKG_BUILD_DIR)/select_event/d_linux_list.h $(1)/usr/include/select_event
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/liblgap.so $(1)/usr/lib/
endef

define Package/liblgap/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/liblgap.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,liblgap))
