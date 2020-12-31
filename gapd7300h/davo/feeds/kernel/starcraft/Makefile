include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=starcraft
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/kernel/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/starcraft
  TITLE:=Kernel driver for kernel starcraft
  SECTION:=kernel
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Kernel modules
  DEPENDS:=+libgcc +libc +librt +!PACKAGE_kmod-qca-ssdk-nohnat:kmod-qca-ssdk-hnat +kmod-ipt-core +kmod-ipt-conntrack +kmod-ipt-nat +kmod-dvosutil
  FILES:=$(PKG_BUILD_DIR)/nf_conntrack_starcraft.ko
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS +=

define KernelPackage/starcraft/install
	echo "KernelPackage/starcraft/install"
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS) -I$(LINUX_DIR)/net/bridge" \
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

ifneq ($(CONFIG_PACKAGE_kmod-starcraft),)
define Build/InstallDev
endef
endif

define KernelPackage/starcraft/install
endef

$(eval $(call KernelPackage,starcraft))

