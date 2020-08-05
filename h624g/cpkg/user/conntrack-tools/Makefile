CFLAGS = -Os -fomit-frame-pointer -Wall

PKG_NAME=conntrack-tools
PKG_VERSION=1.4.2
PKG_DIR=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2

PREFIX=$(CPKG_USER)/build-root
TARGET=conntrack

all:
	@[ -d "$(PREFIX)" ] || exit 1
	@echo Making $(PKG_NAME); \
	if [ ! -d $(PKG_DIR) -a -f $(PKG_SOURCE) ]; then \
		tar xjf $(PKG_SOURCE); \
		for file in $$(ls -A patches/$(PKG_NAME) 2>/dev/null); do \
			pushd $(PKG_NAME); \
			patch -p1 < ../patches/$(PKG_NAME)/$$file; \
			popd; \
		done; \
	fi; \
	pushd $(PKG_DIR); \
	if [ ! -f Makefile ]; then \
		PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig \
		./configure --prefix=$(PREFIX) \
		--build=mips-linux \
		--host=i686-pc-linux-gnu || exit 1; \
	fi; \
	popd
	$(MAKE) -C $(PKG_DIR) $@

install:
	@install -d $(INSTALLDIR)/bin
	@install $(PKG_DIR)/src/$(TARGET) $(INSTALLDIR)/bin
	$(STRIP) $(INSTALLDIR)/bin/$(TARGET)

clean:
	[ -f "$(PKG_DIR)/Makefile" ] && $(MAKE) -C $(PKG_DIR) $@

