# Copyright (c) 2013 The Linux Foundation. All rights reserved.
# allow for local directory containing source to be used

LOCAL_SRC ?= $(TOPDIR)/qca/src/$(PKG_NAME)

ifeq (exists, $(shell [ -d $(LOCAL_SRC) ] && echo exists))
# DAVO modified
#PKG_REV=$(shell cd $(LOCAL_SRC)/; git describe --dirty --long --always | sed 's/.*-g//g')
PKG_REV=
PKG_VERSION:=g$(PKG_REV)
PKG_SOURCE_URL:=
# DAVO modified
#PKG_UNPACK=mkdir -p $(PKG_BUILD_DIR); $(CP) $(LOCAL_SRC)/* $(PKG_BUILD_DIR)/
PKG_UNPACK=$(shell if [ ! -e $(PKG_BUILD_DIR)/.static_used ]; then echo "mkdir -p $(PKG_BUILD_DIR); $(CP) $(LOCAL_SRC)/* $(PKG_BUILD_DIR)/"; fi)
endif
