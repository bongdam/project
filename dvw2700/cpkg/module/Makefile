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
