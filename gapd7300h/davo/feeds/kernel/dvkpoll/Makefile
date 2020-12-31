include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=dvkpoll
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/kernel/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/dvkpoll
  TITLE:=Kernel driver for kernel poll
  SECTION:=kernel
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Kernel modules
  DEPENDS:=+libgcc +libc +librt +kmod-dvfwinfo
  FILES:=$(PKG_BUILD_DIR)/dvkpoll.ko
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

#TARGET_LDFLAGS += -lubus -lubox -lblobmsg_json

define Build/InstallDev
	echo "Build/InstallDev"
endef

define KernelPackage/dvkpoll/install
	echo "KernelPackage/dvkpoll/install"
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

ifneq ($(CONFIG_PACKAGE_kmod-dvkpoll),)
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/dvkpoll
	$(CP) -rf $(PKG_BUILD_DIR)/dvkpoll.h $(1)/usr/include/dvkpoll
	$(CP) -rf $(PKG_BUILD_DIR)/dvkpoll_ioctl.h $(1)/usr/include/dvkpoll
endef
endif

define KernelPackage/dvkpoll/install
endef

$(eval $(call KernelPackage,dvkpoll))

