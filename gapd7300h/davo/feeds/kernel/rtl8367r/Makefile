include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=rtl8367r
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/kernel/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/rtl8367r
  TITLE:=Kernel driver for rtl8367r
  SECTION:=kernel
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Kernel modules
  DEPENDS:=+libgcc +libc +kmod-dvbrdio +kmod-dvflag
  FILES:=$(PKG_BUILD_DIR)/rtl8367r.ko
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include \
	-O1 -DRTL_TBLDRV -D__linux__ \
	-DRTL865X_OVER_KERNEL -DRTL865X_OVER_LINUX -Wno-implicit \
	-I$(PKG_BUILD_DIR)
	#-mno-memcpy

#EXTRA_AFLAGS += $(EXTRA_CFLAGS)

define Build/InstallDev
	echo "Build/InstallDev"
endef

define KernelPackage/rtl8367r/install
	echo "KernelPackage/rtl8367r/install"
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS) -I$(BUILD_DIR)/dv_pkg $(TARGET_CFLAGS)" \
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

ifneq ($(CONFIG_PACKAGE_kmod-rtl8367r),)
define Build/InstallDev
	#$(INSTALL_DIR) $(1)/usr/include/rtl8367r
	#$(CP) -rf $(PKG_BUILD_DIR)/rtl8367r.h $(1)/usr/include/rtl8367r
endef
endif

define KernelPackage/rtl8367r/install
endef

$(eval $(call KernelPackage,rtl8367r))

