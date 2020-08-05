obj-$(CONFIG_DVFLAG) += link.o
obj-y += mib.o
obj-y += acl.o
obj-y += l2.o

ifneq ($(strip $(RTL819X_FLAGS)),)
EXTRA_CFLAGS = $(RTL819X_FLAGS)
endif

staging:
	cp -u acl_write.h $(STAGING_DIR)/include
