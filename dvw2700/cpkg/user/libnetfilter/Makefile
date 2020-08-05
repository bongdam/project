CFLAGS += -Os -fomit-frame-pointer -Wall
libs = libnfnetlink-1.0.1 libmnl-1.0.3 libnetfilter_conntrack-1.0.5

all: prepare
	@for lib in $(libs); do \
		$(MAKE) -C $${lib}; \
		install -d $(INSTALLDIR)/usr/lib; \
		cp -a $${lib}/src/.libs/*.so* $(INSTALLDIR)/usr/lib; \
	done

install: prepare all
	install -d $(INSTALLDIR)/usr/lib
	@for lib in $(libs); do \
		cp -a $${lib}/src/.libs/*.so* $(INSTALLDIR)/usr/lib; \
		$(STRIP) $$(readlink -f $(INSTALLDIR)/usr/lib/$${lib//-*/}.so); \
	done

clean:
	@for lib in $(libs); do \
		if [ -d $${lib} ]; then \
			$(MAKE) -C $${lib} clean; \
		fi; \
	done

prepare:
	@for lib in $(libs); do \
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
			LIBMNL_CFLAGS='-I$(CPKG_USER)/libnetfilter/libmnl-1.0.3/include' \
			LIBMNL_LIBS='-L$(CPKG_USER)/libnetfilter/libmnl-1.0.3/src/.libs -lmnl' \
			LIBNFNETLINK_CFLAGS='-I$(CPKG_USER)/libnetfilter/libnfnetlink-1.0.1/include' \
			LIBNFNETLINK_LIBS='-L$(CPKG_USER)/libnetfilter/libnfnetlink-1.0.1/src/.libs -lnfnetlink' \
			./configure --build=mips-linux --host=i686-pc-linux-gnu --enable-static --enable-shared || exit 1; \
		fi; \
		popd; \
	done
