include $(DIR_USERS)/.config

model_lower_case := $(shell echo $(PROFILE) | tr '[:upper:]' '[:lower:]')
ifneq ($(strip $(model_lower_case)),)
CFLAGS += -DDV_PRODUCT_NAME_LOWERCASE=\"$(model_lower_case)\"
CFLAGS += -DDV_PRODUCT_NAME_UPPERCASE=\"$(shell echo $(model_lower_case) | tr '[:lower:]' '[:upper:]')\"
endif
CFLAGS += -D__SERVICE_LGU_HOME__
CFLAGS += -O2 -fomit-frame-pointer
CFLAGS += -I$(shell pwd)/include

# keep original source
CFLAGS += -DSTRLEN=strlen -DSTRTOK_R=strtok_r -DSTRNCASECMP=strcasecmp -Dnv_strcmp=strcmp -Dyexecv_safe=yexecv -Dyexecl_safe=yexecl -DDVLOG_MARK_ADMIN=\"\" -DMAX_WL_BSS=5

TARGET_LDFLAGS := -L$(STAGING_DIR)/lib
TARGET_LIBS := -lnvram -lshared

ifneq ($(strip $(CONFIG_LIB_SSL)),)
CFLAGS += -DWITH_OPENSSL -I$(STAGING_DIR)/usr/include
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib
TARGET_LIBS += -lssl -lcrypto
endif

GSOAP_DIR=$(shell GSOAP_DIR=`find $(SRCBASE)/gsoap -type d -name plugin -exec readlink -f {} \; | grep -v compiler`; echo $${GSOAP_DIR%/*})

subdir := cwmpClient

all: am_make
	@cd ./cwmpClient; \
	if [ ! -f Makefile ]; then \
		./configure --host=mips-linux \
		CFLAGS='$(strip $(CFLAGS))' \
		$(if $(strip $(TARGET_LDFLAGS)),LDFLAGS="$(TARGET_LDFLAGS)") \
		$(if $(strip $(TARGET_LIBS)),LIBS="$(TARGET_LIBS)") \
		--prefix=$(STAGING_DIR) \
		--sbindir=$(INSTALLDIR)/usr/sbin; \
	fi; \
	cd -
	@test -f "$(subdir)/Makefile" && \
	$(MAKE) GSOAP_DIR=$(GSOAP_DIR) \
	COMMON_LDFLAGS="-lytool -lfurl -lgsoapssl" \
	MTD_LDFLAGS=-lshared \
	CFG_LDFLAGS=-lnvram \
	-C $(subdir) $@ || exit $$?

clean:
	@test -f "$(subdir)/Makefile" && $(MAKE) -C $(subdir) $@ || true
	@cd ./cwmpClient; \
	if [ -f Makefile ]; then \
		make distclean; \
	fi; \
	cd -

install:
ifneq ($(STAGING_DIR),$(INSTALLDIR))
	@[ ! -f "$(subdir)/Makefile" ] || $(MAKE) -C $(subdir) install-exec-hook
endif

.PHONY: all clean install am_make
