PKG_NAME := xl2tpd
PKG_BASE := 1.3.10
PKG_PATCH :=
PKG_VERSION := $(PKG_BASE)$(PKG_PATCH)
PKG_SOURCE := $(wildcard $(PKG_NAME)-$(PKG_VERSION).*)

$(if $(PKG_SOURCE),,$(error $(PKG_NAME)-$(PKG_VERSION) not found))
PKG_BUILD_DIR ?= $(PKG_NAME)$(if $(PKG_VERSION),-$(PKG_VERSION))

all: depend
	$(MAKE) -C $(PKG_BUILD_DIR) KERNELSRC=$(STAGING_DIR) $(PKG_NAME)

depend:
	@if [ ! -d $(PKG_BUILD_DIR) -a -f $(PKG_SOURCE) ]; then \
		tar xaf $(PKG_SOURCE); \
		for file in $$(ls -A patches/ 2>/dev/null); do \
			pushd $(PKG_BUILD_DIR); \
			patch -p1 < ../patches/$$file; \
			popd; \
		done; \
	fi

install:
ifneq ($(STAGING_DIR),$(INSTALLDIR))
	@install -d $(INSTALLDIR)/bin
	@[ ! -d "$(PKG_BUILD_DIR)" ] || { \
		install -m 0755 $(PKG_BUILD_DIR)/$(PKG_NAME) $(INSTALLDIR)/bin/$(PKG_NAME); \
		$(STRIP) $(INSTALLDIR)/bin/$(PKG_NAME); \
	}
endif

clean:
	[ ! -f "$(PKG_BUILD_DIR)/Makefile" ] || $(MAKE) -C $(PKG_BUILD_DIR) $@

.PHONY: all install clean depend
