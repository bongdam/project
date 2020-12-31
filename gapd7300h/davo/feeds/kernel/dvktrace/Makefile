include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=dvktrace
PKG_RELEASE:=1

PKG_MAINTAINER:=Davolink <davolink@davolink.co.kr>
PKG_BUILD_DIR:=$(BUILD_DIR)/dv_pkg/kernel/$(PKG_NAME)

#PKG_INSTALL:=1
include $(INCLUDE_DIR)/package.mk

define KernelPackage/dvktrace
  TITLE:=Kernel driver for kernel trace
  SECTION:=kernel
  CATEGORY:=DAVOLINK Proprietary software
  SUBMENU:=Kernel modules
  DEPENDS:=+libgcc +libc +librt
  FILES:=$(PKG_BUILD_DIR)/dvktrace.ko
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include

TARGET_LDFLAGS += -lubus -lubox -lblobmsg_json

define KernelPackage/dvktrace/install
	echo "KernelPackage/dvktrace/install"
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

ifneq ($(CONFIG_PACKAGE_kmod-dvktrace),)
define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/dvktr
	$(CP) -rf $(PKG_BUILD_DIR)/dvktr_ioctl.h $(1)/usr/include/dvktr
	$(CP) -rf $(PKG_BUILD_DIR)/dvktr_dev.h $(1)/usr/include/dvktr
	ln -sf $(LINUX_DIR)/include/uapi/linux/dv_wlan_priv.h $(1)/usr/include/dv_wlan_priv.h
endef
endif

define KernelPackage/dvktrace/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/dvktr.init $(1)/etc/init.d/dvktr
endef

$(eval $(call KernelPackage,dvktrace))

