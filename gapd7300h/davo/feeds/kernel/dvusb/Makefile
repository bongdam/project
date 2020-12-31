include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=dvusb
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/kernel/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/dvusb
  TITLE:=Kernel driver for dvusb
  SECTION:=kernel
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Kernel modules
  DEPENDS:=+libgcc +libc +librt +kmod-dvktrace
  FILES:=$(PKG_BUILD_DIR)/dvusb.ko
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += -lubus -lubox -lblobmsg_json

define Build/InstallDev
	echo "Build/InstallDev"
endef

define KernelPackage/dvusb/install
	echo "KernelPackage/dvusb/install"
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

ifneq ($(CONFIG_PACKAGE_kmod-dvusb),)
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/dvusb
	$(CP) -rf $(PKG_BUILD_DIR)/dvusb_ioctl.h $(1)/usr/include/dvusb
endef
endif

define KernelPackage/dvusb/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/dvusb.init $(1)/etc/init.d/dvusb
endef

$(eval $(call KernelPackage,dvusb))

