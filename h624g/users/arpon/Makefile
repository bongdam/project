CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
LD = $(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip
CFLAGS = -DLINUX -I$(DIR_ROOT)/users/arpon/extlib/include
LDFLAGS = -L$(DIR_ROOT)/users/arpon/extlib/lib
TARGET = arpon
OBJ = arpon.o

.SUFFIXES : .c .o

all: prepare_libdnet prepare_libnet prepare_libpcap
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) arpon.c -lpthread -ldnet -lnet -lpcap
	$(STRIP) --strip-debug $(TARGET)

prepare_libdnet:
	cd ./libdnet-1.11; \
	if [ ! -f Makefile ]; then \
		CC=$(CC) ./configure --host=mips-linux --build=i686 --enable-static=yes --enable-shared=no --prefix=$(DIR_ROOT)/users/arpon/extlib; \
	fi; \
	make -j 4; \
	make install-strip; \
	cd ..

prepare_libnet:
	cd ./libnet-1.2-rc3; \
	if [ ! -f Makefile ]; then \
		CC=$(CC) ./configure --host=mips-linux --build=i686 --enable-static=yes --enable-shared=no --prefix=$(DIR_ROOT)/users/arpon/extlib; \
	fi; \
	make -j 4; \
	make install-strip; \
	cd ..

prepare_libpcap:
	cd ./libpcap-1.6.2; \
	if [ ! -f Makefile ]; then \
		CC=$(CC) ./configure --host=mips-linux --build=i686 --enable-shared=no --enable-yydebug=no --enable-can=no \
			--enable-optimizer-dbg=no --enable-ipv6=no --with-dag=no --with-sita=no --prefix=$(DIR_ROOT)/users/arpon/extlib --with-pcap=linux; \
	fi; \
	make -j 4; \
	make install; \
	$(STRIP) --strip-debug $(DIR_ROOT)/users/arpon/extlib/lib/libpcap.a
	cd ..

clean:
	-make -C ./libdnet-1.11 distclean
	-make -C ./libnet-1.2-rc3 distclean
	-make -C ./libpcap-1.6.2 distclean
	rm -rf ./extlib/*
	rm -f $(TARGET) *.o	

romfs:
	$(ROMFSINST) arpon.sarpi /var/arpon.sarpi
	$(ROMFSINST) $(TARGET) /bin/$(TARGET)
