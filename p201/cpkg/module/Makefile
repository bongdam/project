ifeq ($(MAKECMDGOALS),staging)
include $(DIR_LINUX)/.config
endif

obj-y += sysvar/
obj-$(CONFIG_BRDIO) += brdio/
obj-$(CONFIG_DVFLAG) += dvflag/
obj-$(CONFIG_BCMNVRAM) += bcmnvram/
obj-y += nettweak/

ifneq ($(strip $(CPKG_MODULE)),)
clean-files := $(shell (cd $(CPKG_MODULE); find . \( -name '*.[oas]' -o \
				 -name '*.ko' -o \
				 -name '.*.cmd' -o \
				 -name '.*.d' -o \
				 -name '.*.tmp' -o \
				 -name '*.mod.c' -o \
				 -name 'modules.*' \) -type f -print))
endif

staging:
ifneq ($(strip $(STAGING_DIR)),)
	@mkdir -p $(STAGING_DIR)/include
	@$(MAKE) -C lib $@ || true
	@$(if $(CONFIG_BRDIO),$(MAKE) -C brdio $@ || true)
	@$(if $(CONFIG_DVFLAG),$(MAKE) -C dvflag $@ || true)
	@$(if $(CONFIG_BCMNVRAM),$(MAKE) -C bcmnvram $@ || true)
	@$(if $(CONFIG_RTL_819X_SWCORE),$(MAKE) -C rtl819x $@ || true)
endif

.PHONY: staging
