obj-y += nettweak.o
nettweak-y := in_ipv4_addr.o
nettweak-y += port_censor.o
nettweak-y += brnf_forward_passthru.o
nettweak-$(CONFIG_NEIGH_UNSOLICITED_ADD) += unsol_neigh.o
# nettweak-y += dlf_limit_entry.o
nettweak-$(CONFIG_NF_NAT_TWINIP) += twin_ip.o
nettweak-$(CONFIG_IN_MULTICAST_SNOOP) += group_snoop.o

CFLAGS_port_censor.o = -I$(CPKG_USER)/include -I$(srctree)/drivers/net/rtl819x
CFLAGS_unsol_neigh.o = -I$(CPKG_USER)/include -I$(srctree)/drivers/net/rtl819x
CFLAGS_dlf_limit_entry.o = -I$(CPKG_USER)/include -I$(srctree)/drivers/net/rtl819x
