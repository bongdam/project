obj-y += sysvar/
obj-y += dvflag/
obj-y += brdio/
obj-y += dv_bs/
obj-$(CONFIG_BCMNVRAM) += bcmnvram/
obj-$(CONFIG_NF_NAT_BATTLENET) += scraft/
obj-y += nettweak/

ifneq ($(strip $(CPKG_MODULE)),)
clean-files := $(shell (cd $(CPKG_MODULE); find . \( -name '*.[oas]' -o \
				 -name '*.ko' -o \
				 -name '.*.cmd' -o \
				 -name '.*.d' -o \
				 -name '.*.tmp' -o \
				 -name '*.mod.c' -o \
				 -name 'modules.order' \) -type f -print))
endif
