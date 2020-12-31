include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=dvbrdio
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/kernel/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/dvbrdio
  TITLE:=Kernel driver for dvbrdio
  SECTION:=kernel
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Kernel modules
  DEPENDS:=+libgcc +libc
  FILES:=$(PKG_BUILD_DIR)/dvbrdio.ko
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

define Build/InstallDev
	echo "Build/InstallDev"
endef

define KernelPackage/dvbrdio/install
	echo "KernelPackage/dvbrdio/install"
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS) -I$(BUILD_DIR)/dv_pkg" \
		modules
endef

define Build/Clean
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		clean
endef

ifneq ($(CONFIG_PACKAGE_kmod-dvbrdio),)
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/dvbrdio
	$(CP) -rf $(PKG_BUILD_DIR)/dvbrdio.h $(1)/usr/include/dvbrdio
endef
endif

define KernelPackage/dvbrdio/install
endef

$(eval $(call KernelPackage,dvbrdio))

