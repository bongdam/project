CFLAGS = -Os -fomit-frame-pointer -Wall
LD = $(CROSS_COMPILE)ld
libs += libmnl-1.0.3
libs += libnfnetlink-1.0.1
libs += libnetfilter_cthelper-1.0.0
libs += libnetfilter_log-1.0.1
libs += libnetfilter_conntrack-1.0.5
libs += libnetfilter_cttimeout-1.0.0
libs += libnetfilter_queue-1.0.2

PREFIX=$(CPKG_USER)/build-root

all: prepare
	@for lib in $(libs); do \
		$(MAKE) -C $${lib}; \
		install -d $(INSTALLDIR)/usr/lib; \
		cp -a $${lib}/src/.libs/*.so* $(INSTALLDIR)/usr/lib; \
	done

install: prepare all
	@install -d $(INSTALLDIR)/usr/lib
	@[ -d "$(PREFIX)/lib" ] && { \
		pushd $(PREFIX)/lib; \
		tar cf - $$(find . -maxdepth 1 -name "*.so*") | (cd $(INSTALLDIR)/usr/lib && tar xBf -); \
		popd; \
	}

clean:
	@for lib in $(libs); do \
		[ -f "$${lib}/Makefile" ] && $(MAKE) -C $${lib} $@; \
	done

prepare:
	@[ -d "$(PREFIX)" ] || { \
		rm -rf "$(PREFIX)"; \
		mkdir "$(PREFIX)"; \
	}

	@for lib in $(libs); do \
		@echo Making $${lib}; \
		if [ ! -d $${lib} -a -f $${lib}.tar.bz2 ]; then \
			tar xjf $${lib}.tar.bz2; \
			for file in $$(ls -A patches/$${lib//-*/} 2>/dev/null); do \
				pushd $${lib}; \
				patch -p1 < ../patches/$${lib//-*/}/$$file; \
				popd; \
			done; \
		fi; \
		pushd $${lib}; \
		if [ ! -f Makefile ]; then \
			PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig \
			./configure --prefix=$(PREFIX) \
			--build=mips-linux \
			--host=i686-pc-linux-gnu \
			--enable-static=no --enable-shared || exit 1; \
		fi; \
		popd; \
		$(MAKE) -C $${lib} install; \
	done
