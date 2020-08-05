CFLAGS += -Os -fomit-frame-pointer -Wall
CFLAGS += -I$(DIR_LINUX)/drivers/net/wireless/rtl8192cd -I$(DIR_USERS)/boa/apmib
LDFLAGS = -L$(STAGING_DIR)/lib -lnvram
CFLAGS_display := -fpic
CFLAGS_furl := -fpic

TARGET = libfurl.so
OBJS := display.o furl.o

.PHONY: clean install

all: $(TARGET) furl

$(TARGET): $(OBJS)
	$(CC) -shared -Wl,-soname,$(TARGET) -o $(TARGET) $(OBJS)

furl: fota.o main.o $(TARGET)
	$(CC) -o $@ $(filter %.o,$+) -L$(STAGING_DIR)/lib -lnvram -lytool -L. -lfurl

clean:
	@rm -f $(TARGET) furl *.o .*.depend

install: all
	$(if $(STAGING_DIR),mkdir -p $(STAGING_DIR)/include && cp -u furl.h goods.h $(STAGING_DIR)/include)
	install -d $(INSTALLDIR)/lib
	install -m 755 $(TARGET) $(INSTALLDIR)/lib
	$(STRIP) $(INSTALLDIR)/lib/$(TARGET)
	install -d $(INSTALLDIR)/usr/bin
	install furl $(INSTALLDIR)/usr/bin
	@for app in ub fota_check fota_upgrade; do ln -sf furl $(INSTALLDIR)/usr/bin/$${app}; done

%.o: .%.depend
.%.depend: %.c
	@$(CC) $(CFLAGS) -M $< > $@
	@echo -n -e "\t" >> $@
	@echo '$(CC) $(CFLAGS_$*) $(CFLAGS) -c $< -o $*.o' >> $@

ifneq ($(MAKECMDGOALS),clean)
-include $(OBJS:%.o=.%.depend)
endif
