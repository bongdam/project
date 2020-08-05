#
# TMS Client Makefile
#

CFLAGS += -g -O2 -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_USERS)/openssl-1.0.2d/include
LDFLAGS = -L$(SRCBASE)/nvram -lnvram
LDFLAGS += -L$(SRCBASE)/furl -lfurl
LDFLAGS += -L$(SRCBASE)/libytool -lytool

TARGET = tms

OBJS = tms_client.o tms_client_private.o tms_misc.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(DIR_USERS)/openssl-1.0.2d/libcrypto.a

clean:
	rm -f $(OBJS) $(TARGET) $(OBJS:%.o=.%.depend)

install:
	install -m 755 $(TARGET) $(INSTALLDIR)/bin
	$(STRIP) $(INSTALLDIR)/bin/$(TARGET)

%.o: .%.depend
.%.depend: %.c
	$(CC) $(CFLAGS) -M $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
