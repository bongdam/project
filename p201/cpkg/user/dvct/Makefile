CFLAGS := -O2 -Wall -Werror -Wno-unused-result

all: dvct_roll dvct_unroll

dvct_roll: dvct.c libdvct.h
	cc $(CFLAGS) -o $@ $< -lcrypto

dvct_unroll: dvct.c libdvct.h
	$(CC) $(CFLAGS) -I$(STAGING_DIR)/usr/include -o $@ $< -L$(STAGING_DIR)/usr/lib -lcrypto

clean:
	@rm -f dvct_roll dvct_unroll

install: all
	$(if $(STAGING_DIR),mkdir -p $(STAGING_DIR)/include && cp -u libdvct.h $(STAGING_DIR)/include)
	@install -d $(INSTALLDIR)/bin
	@install -m 755 dvct_unroll $(INSTALLDIR)/bin

.PHONY: all install clean
