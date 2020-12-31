#!/bin/sh
# Copyright (C) 2009 OpenWrt.org

setup_hw_nat() {
	local hw_nat=$(uci -q get system.system.hw_nat)
	if [ "$hw_nat" = "1" ]; then
		echo 1 > /proc/sys/net/netfilter/nf_conntrack_tcp_no_window_check
		ssdk_sh nat global set enable disable
	fi
	return;
}

dhcp_acl_rule_set() {
	local tmp=$(mktemp /tmp/XXXXXX)
	local op
	for i in 1 2 3 4; do
		echo "acl list $1 99 0 0 $i" >> $tmp
	done
	echo "quit" >> $tmp
	chmod 755 $tmp
	ssdk_sh < $tmp >&-
	rm $tmp
#	[ "$1" = "unbind" ] && op="-D" || op="-I"
#	iptables $op FORWARD -p udp --dport 67:68 -m physdev --physdev-is-bridged -j DROP 2>/dev/null
}

dhcp_snoop_apply() {
	dhcp_acl_rule_set "unbind"
	if [ "$(uci -q get dhcp.dnsmasq.dhcp_protection)" -gt "0" ]; then
		dhcp_acl_rule_set "bind"
	fi
}

iapp_set_ports() {
	local port

	if [ "$(uci -q get dvui.network.opmode)" = "bridge" ]; then
		port=0x00
	else
		port=0x3d
	fi

	uci set network.filterIAPP1.port_bitmap="$port"
	uci set network.filterIAPP2.port_bitmap="$port"
	uci set network.filterIAPP3.port_bitmap="$port"
	uci commit network
}

setup_switch_dev() {
	local name
	config_get name "$1" name
	name="${name:-$1}"
	[ -d "/sys/class/net/$name" ] && ifconfig "$name" up
	swconfig dev "$name" load network
#	srate &

	if [ "$(uci -q get dvui.network.opmode)" == "bridge" ]; then
		swconfig dev "$name" extload network_bridge
	else
		swconfig dev "$name" extload network_nat
	fi

#	# Firewall
#	sh /lib/network/scripts/dos.sh "$name"
#
#	# SKBB
#	ssdk_sh debug reg set 0x810 0x55443201 4 > /dev/null 2>&1
#
#	# Repeater mode
#	# [ "$(uci -q get dvui.network.repeater)" = 1 ] && ssdk_sh port poweroff set 1 > /dev/null 2>&1
}

setup_ipg_shrinking()
{
	ssdk_sh debug reg set 0x0070 0xb00ee059 4 > /dev/null

#	ssdk_sh rate portshaper set 5 enable y 1000032 500000 0 0
#	ssdk_sh rate portshaper set 1 enable y 1000032 500000 0 0
#	ssdk_sh rate portshaper set 2 enable y 1000032 500000 0 0
#	ssdk_sh rate portshaper set 3 enable y 1000032 500000 0 0
#	ssdk_sh rate portshaper set 4 enable y 1000032 500000 0 0

}

setup_sw_qos()
{
	ssdk_sh debug reg set 0x097c 0x00cf 4 > /dev/null
	ssdk_sh debug reg set 0x0984 0x00cf 4 > /dev/null
	ssdk_sh debug reg set 0x098c 0x00cf 4 > /dev/null
	ssdk_sh debug reg set 0x0994 0x00cf 4 > /dev/null
}

setup_switch() {
	clone_mac=$(uci_get network wan macaddr)
	if [ -n "$clone_mac" ]; then
		ifconfig eth0 hw ether $clone_mac
		echo "macclone enable" > /proc/loop_check
	else
		macaddr=$(fw_printenv -n ethaddr)
		if [ -n "$macaddr" ]; then
			ifconfig eth0 hw ether $macaddr
		fi
		echo "macclone disable" > /proc/loop_check
	fi

	local lan_macaddr=$(uci_get "network.lan.macaddr")         
	if [ -n "$lan_macaddr" ]; then                             
		ifconfig eth1 hw ether $lan_macaddr                                                    
	fi 

	if [ "$(uci -q get network.loopcheck.enable)" = "1" ]; then
		echo "enable" > /proc/loop_check
	else
		echo "disable" > /proc/loop_check
	fi
	
#	iapp_set_ports
#
	config_load network
	config_foreach setup_switch_dev switch
	net_mode=$(uci -q get dvui.network.opmode)
#
#	ssdk_sh debug reg set 0x0050 0xcc35cc35 4
#	ssdk_sh debug reg set 0x0054 0xcb35cb35 4
#	ssdk_sh debug reg set 0x0058 0xcb35cb35 4
#	ssdk_sh debug reg set 0x005c 0x03ffff00 4
#
	if [ "$net_mode" = "nat" ]; then
#		dhcp_snoop_apply

		setup_hw_nat
#
#        # enable : br-wan                                                                    
#        # disable: eth0.2             
#        bridge_mode=$(uci -q get network.wan.type)
#        if [ "$bridge_mode" = "bridge" ]; then                                                 
#            ssdk_sh nat global set enable disable enable
#        else                              
#            ssdk_sh nat global set enable disable disable
#        fi 
#		if [ "$(uci -q get dvmgmt.misc.ssdk_nat)" = "qos" ]; then
#			echo 0 > /sys/ssdk_napt/allow_0_tos
#		elif [ "$(uci -q get dvmgmt.misc.ssdk_nat)" = "normal" ]; then
#			echo 1 > /sys/ssdk_napt/allow_0_tos
#		fi
	fi
#	# DAVO QCA-50
#	if [ "$(uci -q get network.portspeed_1.speed)" = "1000" ]; then
#		ssdk_sh port autoadv set 1 0x600
#		ssdk_sh port autoneg enable 1
#	fi
#	if [ "$(uci -q get network.portspeed_2.speed)" = "1000" ]; then
#		ssdk_sh port autoadv set 2 0x600
#		ssdk_sh port autoneg enable 2
#	fi
#	if [ "$(uci -q get network.portspeed_3.speed)" = "1000" ]; then
#		ssdk_sh port autoadv set 3 0x600
#		ssdk_sh port autoneg enable 3
#	fi
#	if [ "$(uci -q get network.portspeed_4.speed)" = "1000" ]; then
#		ssdk_sh port autoadv set 4 0x600
#		ssdk_sh port autoneg enable 4
#	fi
#	if [ "$(uci -q get network.portspeed_5.speed)" = "1000" ]; then
#		ssdk_sh port autoadv set 5 0x600
#		ssdk_sh port autoneg enable 5
#	fi

#	switch IPG control
#	ssdk_sh debug reg set 0x009c 0x28 4
#	ssdk_sh debug reg set 0x00a0 0x20 4
#	ssdk_sh debug reg set 0x00a4 0x20 4
#	ssdk_sh debug reg set 0x00a8 0x20 4
#	ssdk_sh debug reg set 0x00ac 0x20 4
#	ssdk_sh debug reg set 0x00b0 0x20 4

	if [ "$(uci -q get dvui.network.opmode)" = "bridge" ]; then
		echo 0 > /proc/sys/net/edma/default_group2_bmp
		echo 62 > /proc/sys/net/edma/default_group1_bmp
	else
		echo 30 > /proc/sys/net/edma/default_group2_bmp
		echo 32 > /proc/sys/net/edma/default_group1_bmp
	fi
	config_get proto wan proto
	setup_ipg_shrinking
	if [ "$proto" = "static" ]; then
		if [ "$(uci -q get dvui.network.opmode)" = "bridge" ]; then
			echo linkshape 0 > /proc/dvbrdio
		fi
	fi

	if [ "$(uci -q get dvui.network.sw_qos)" = "1" ]; then
		setup_sw_qos
	fi

	if [ -d /proc/rtl8367r ]; then
		echo phy_set > /proc/rtl8367r/control
	fi
}

