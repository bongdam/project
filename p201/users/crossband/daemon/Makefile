#CC=rsdk-linux-gcc

include  $(DIR_LINUX)/.config

CFLAGS := -s -Wall -c -Os $(CFLAGS)
LDFLAGS = -s -Wall

ifeq ($(SLINK),1)
CFLAGS  += -ffunction-sections -fdata-sections
LDFLAGS += --static -s -Wl,--gc-sections
endif

CFLAGS += $(COMMON_CFLAGS)

all:		crossband_daemon

crossband_daemon:		crossband_daemon.o
			$(CC) $(LDFLAGS) -o crossband_daemon crossband_daemon.o 

clean:
			rm -f *.o
			rm -f crossband_daemon

romfs:
	$(ROMFSINST) crossband_daemon /bin/crossband_daemon

crossband_daemon.o:		crossband_daemon.c 
			$(CC) $(CFLAGS) -o crossband_daemon.o crossband_daemon.c
