include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=dvgpioreset
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/kernel/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/dvgpioreset
  TITLE:=Kernel Driver for gpio reset
  SECTION:=kernel
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Kernel modules
  DEPENDS:=+libgcc +libc +librt
  FILES:=$(PKG_BUILD_DIR)/dvgpioreset.ko
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

define Build/InstallDev
	echo "Build/InstallDev"
endef

define KernelPackage/dvgpioreset/install
	echo "KernelPackage/dvgpioreset/install"
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
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

ifneq ($(CONFIG_PACKAGE_kmod-dvgpioreset),)
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/dvgpioreset
	$(CP) -rf $(PKG_BUILD_DIR)/dvgpioreset_ioctl.h $(1)/usr/include/dvgpioreset
endef
endif

define KernelPackage/dvgpioreset/install
endef

$(eval $(call KernelPackage,dvgpioreset))

