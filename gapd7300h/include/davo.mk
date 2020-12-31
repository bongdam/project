DVCONF_CDEFS:=
DVCONF_CDEFS += DVLOG_MARK=\"[_DV^]\"
DVCONF_CDEFS += DVLOG_MARK_USER=DVLOG_MARK\"[U]\"
DVCONF_CDEFS += DVLOG_MARK_ADMIN=DVLOG_MARK\"[A]\"
DVCONF_CDEFS += DVLOG_MARK_TR069=DVLOG_MARK\"[T]\"

###############################################################################
# WAN_PORT
# LAN_PORT0 / LAN_PORT1 / LAN_PORT2 / LAN_PORT3
# CPU_PORT
#------------------------------------------------------------------------------
DVCONF_CDEFS += DV_WAN_PORT=\"5\"
DVCONF_CDEFS += DV_LAN_PORT1=\"1\"
DVCONF_CDEFS += DV_LAN_PORT2=\"2\"
DVCONF_CDEFS += DV_LAN_PORT3=\"3\"
DVCONF_CDEFS += DV_LAN_PORT4=\"4\"
DVCONF_CDEFS += DV_CPU_PORT=\"0\"
# usage  DV_PORT_NUM(DV_WAN_PORT) ==> digit 1
DVCONF_CDEFS += "DV_PORT_NUM(x)=((x)[0]-0x30)"

###############################################################################
# TARGET_COMPANY
#------------------------------------------------------------------------------
CONFIG_TARGET_COMPANY=lgu
ifeq ($(CONFIG_TARGET_COMPANY),lgu)
	export CONFIG_COMPANY_LGU=y
	DVCONF_CDEFS += __LGUPLUS__
endif

ifeq ($(PROFILE),gapd7300)
DVCONF_CDEFS += DV_PRODUCT_NAME_LOWERCASE=\"gapd-7300\"
DVCONF_CDEFS += DV_PRODUCT_NAME_UPPERCASE=\"GAPD-7300\"
else ifeq ($(PROFILE),gapd7200)
DVCONF_CDEFS += DV_PRODUCT_NAME_LOWERCASE=\"gapd-7200\"
DVCONF_CDEFS += DV_PRODUCT_NAME_UPPERCASE=\"GAPD-7200\"
else
DVCONF_CDEFS += DV_PRODUCT_NAME_LOWERCASE=\"gapd-7300h\"
DVCONF_CDEFS += DV_PRODUCT_NAME_UPPERCASE=\"GAPD-7300H\"
endif
DVCONF_CDEFS += __DAVO_LGHV__
DVCONF_CDEFS += __DAVO_SSHD__

###############################################################################
# WIRELESS INTERFACE INFO
#------------------------------------------------------------------------------
DVCONF_CDEFS += MAX_WL_INTF=2
DVCONF_CDEFS += MAX_WL_BSS=8

###############################################################################
# CONFIG_NF_NAT_TWINIP
#------------------------------------------------------------------------------
CONFIG_NF_NAT_TWINIP=y
ifeq ($(CONFIG_NF_NAT_TWINIP),y)
	export CONFIG_NF_NAT_TWINIP=y
	DVCONF_CDEFS += CONFIG_NF_NAT_TWINIP
endif
CONFIG_NF_NAT_PROTO_RESERVED=y
ifeq ($(CONFIG_NF_NAT_PROTO_RESERVED),y)
	export CONFIG_NF_NAT_PROTO_RESERVED=y
DVCONF_CDEFS += CONFIG_NF_NAT_PROTO_RESERVED
endif

DAVO_DEF := -D__DAVO__
ifneq ($(strip $(DVCONF_CDEFS)),)
DAVO_DEF += $(foreach cdef,$(DVCONF_CDEFS),-D$(cdef))
DAVO_DEF_KERNEL = 
endif

export DAVO_DEF DAVO_DEF_KERNEL
