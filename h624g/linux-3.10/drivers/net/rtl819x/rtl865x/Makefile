#
# Makefile for the Tulip ethernet driver
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile...


ifdef CONFIG_RTL_NFJROM_MP
obj-y += re865x_54e_mp.obj
else
obj-y += re865x_54e_for_davo.obj
endif
#	ifdef CONFIG_IPV6
#		ifdef CONFIG_RTL_PROC_DEBUG
#		obj-y += re865x_54e_ipv6_proc.obj
#		else
#		obj-y += re865x_54e_ipv6.obj
#		endif
#	else
#		ifdef CONFIG_RTL_PROC_DEBUG
#		obj-y += re865x_54e_proc.obj
#		else
#		obj-y += re865x_54e.obj
#		endif
#	endif

EXTRA_CFLAGS += -O1 -DRTL_TBLDRV -D__linux__  -mno-memcpy -DRTL865X_OVER_KERNEL -DRTL865X_OVER_LINUX -Werror

EXTRA_AFLAGS += $(EXTRA_CFLAGS)

