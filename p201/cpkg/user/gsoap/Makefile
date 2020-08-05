PKG_NAME := gsoap
PKG_BASE := 2.7.13
PKG_PATCH :=
PKG_VERSION := $(PKG_BASE)$(PKG_PATCH)
PKG_SOURCE := $(wildcard $(PKG_NAME)_$(PKG_VERSION).*)

$(if $(PKG_SOURCE),,$(error $(PKG_NAME)_$(PKG_VERSION) not found))
PKG_BUILD_DIR ?= $(PKG_NAME)$(if $(PKG_VERSION),-$(shell PKG_VERSION=$(PKG_VERSION); echo $${PKG_VERSION%.*}))

TARGET_LDFLAGS :=
INSTALLDIR := $(DIR_ROMFS)

GSOAP_DISABLE :=
GSOAP_WITHOUT :=

GSOAP_OPTIONS := \
	$(if $(strip $(TARGET_LDFLAGS)),LDFLAGS=$(TARGET_LDFLAGS)) \
	$(if $(strip $(GSOAP_DISABLE)),$(addprefix --disable-,$(GSOAP_DISABLE))) \
	$(if $(strip $(GSOAP_WITHOUT)),$(addprefix --without-,$(GSOAP_WITHOUT)))

all: depend
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) all
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) install
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)-compiler all && \
	cp $(PKG_BUILD_DIR)-compiler/gsoap/src/soapcpp2 $(PKG_BUILD_DIR)/gsoap/src/soapcpp2

depend:
	@if [ ! -d $(PKG_BUILD_DIR) -a -f $(PKG_SOURCE) ]; then \
		unzip $(PKG_SOURCE); \
		for file in $$(ls -A patches/ 2>/dev/null); do \
			pushd $(PKG_BUILD_DIR); \
			patch -p1 < ../patches/$$file; \
			popd; \
		done; \
		cp -fpR $(PKG_BUILD_DIR) $(PKG_BUILD_DIR)-compiler; \
	fi; \
	pushd $(PKG_BUILD_DIR); \
	if [ ! -f config_done ]; then \
		./configure CPPFLAGS="-I$(STAGING_DIR)/usr/include" \
		LDFLAGS="-L$(STAGING_DIR)/usr/lib" \
		ac_cv_func_malloc_0_nonnull=yes \
		--host=mips-linux \
		--prefix=$(STAGING_DIR) \
		$(GSOAP_OPTIONS) && touch config_done; \
	fi; \
	popd; \
	pushd $(PKG_BUILD_DIR)-compiler; \
	if [ ! -f config_done ]; then \
		./configure CC=gcc CXX=g++ AR=ar RANLIB=ranlib CROSS_COMPILE="" \
		--prefix=$(STAGING_DIR) \
		$(GSOAP_OPTIONS) && touch config_done; \
	fi; \
	popd

install:
	@:

clean:
	[ ! -f "$(PKG_BUILD_DIR)/Makefile" ] || $(MAKE) -C $(PKG_BUILD_DIR) $@


.PHONY: all install clean depend
