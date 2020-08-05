.PHONY: genmak romfs

all: genmak
	@$(MAKE) -f Makefile 

romfs:
	@:

genmak:
	@if [ ! -f Makefile ]; then \
		CC=$(CROSS_COMPILE)gcc CXX=$(CROSS_COMPILE)g++ ./configure --build=mips-linux --host=i686-pc-linux-gnu --with-pcap=linux; \
	fi

%: genmak
	@$(MAKE) -f Makefile $* 
