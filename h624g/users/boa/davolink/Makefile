ifeq ($(wildcard $(DIR_LINUX)/.config),)
include ../../../linux-2.6.30/.config
else
include $(DIR_LINUX)/.config
endif

ifeq ($(wildcard $(DIR_USERS)/.config),)
include ../../.config
else
include $(DIR_USERS)/.config
endif

ifndef COMMON_CFLAGS
$(error COMMON_CFLAGS is not defined)
endif

.SUFFIXES:
.SUFFIXES: .o .c
.PHONY: clean all depend

LDFLAGS =  -g
CFLAGS = -Os -pipe
DEPEND = ./.depend

EXTRA_CFLAGS =
DEBUG	= -g -Wall
IFLAGS	= -I.. -I../apmib -I../system -I$(CPKG_USER)/include -include $(DIR_LINUX)/include/generated/autoconf.h
CFLAGS	+= $(COMMON_CFLAGS) $(EXTRA_CFLAGS)

TARGET = libcustom.a

SOURCES += common.c resolv.c conf.c sha256.c services.c
OBJS = $(SOURCES:.c=.o)

all: depend $(TARGET)

$(TARGET): $(OBJS)
	$(AR) ru $@ $(OBJS)

clean:
	rm -f $(DEPEND) $(OBJS) *.so *.a

depend: $(SOURCES)
	if [ ! -e $(DEPEND) ]; then \
		$(CPP) $(DEBUG) $(CFLAGS) $(IFLAGS) -MM $^ > $(DEPEND); \
	fi

-include $(DEPEND)

.c.o:
	$(CC) -c -o $@ $(DEBUG) $(CFLAGS) $(IFLAGS) $<
