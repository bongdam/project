include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=dvhealthchk
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/kernel/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/dvhealthchk
  TITLE:=Kernel Driver for Firmware Info
  SECTION:=kernel
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Kernel modules
  DEPENDS:=+libgcc +libc +librt
  FILES:=$(PKG_BUILD_DIR)/dvhealthchk.ko
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

#TARGET_LDFLAGS += -lubus -lubox -lblobmsg_json

define Build/InstallDev
	echo "Build/InstallDev"
endef

define KernelPackage/dvhealthchk/install
	echo "KernelPackage/dvhealthchk/install"
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

ifneq ($(CONFIG_PACKAGE_kmod-dvhealthchk),)
define Build/InstallDev
endef
endif

define KernelPackage/dvhealthchk/install
endef

$(eval $(call KernelPackage,dvhealthchk))

