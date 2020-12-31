include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=pufcns
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/kernel/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/$(PKG_NAME)
  TITLE:=Kernel Driver for PUF CNS
  SECTION:=kernel
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Kernel modules
  DEPENDS:=+libgcc +libc #+librt
  DEPENDS+=+kmod-dvbrdio
  FILES:=$(PKG_BUILD_DIR)/$(PKG_NAME).ko
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

#TARGET_LDFLAGS += -lubus -lubox -lblobmsg_json

define Build/InstallDev
	echo "Build/InstallDev"
endef

define KernelPackage/$(PKG_NAME)/install
	echo "KernelPackage/$(PKG_NAME)/install"
endef

define KernelPackage/pca9570/description
 Kernel module to use puf chip
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

ifneq ($(CONFIG_PACKAGE_kmod-$(PKG_NAME)),)
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) -rf $(PKG_BUILD_DIR)/pufcns_ioctl.h $(1)/usr/include
endef
endif

define KernelPackage/$(PKG_NAME)/install
endef

$(eval $(call KernelPackage,$(PKG_NAME)))

