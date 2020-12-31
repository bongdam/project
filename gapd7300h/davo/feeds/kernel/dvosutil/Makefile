include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=dvosutil
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/kernel/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/dvosutil
  TITLE:=Kernel Driver for Firmware Info
  SECTION:=kernel
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Kernel modules
  DEPENDS:=+libgcc +libc #+librt
  FILES:=$(PKG_BUILD_DIR)/dvosutil.ko
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

#TARGET_LDFLAGS += -lubus -lubox -lblobmsg_json

define Build/InstallDev
	echo "Build/InstallDev"
endef

define KernelPackage/dvosutil/install
	echo "KernelPackage/dvosutil/install"
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

ifneq ($(CONFIG_PACKAGE_kmod-dvosutil),)
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) -rf $(PKG_BUILD_DIR)/dvosutil.h $(1)/usr/include
endef
endif

define KernelPackage/dvosutil/install
endef

$(eval $(call KernelPackage,dvosutil))

