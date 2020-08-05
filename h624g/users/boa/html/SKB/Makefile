ifeq ($(wildcard $(DIR_LINUX)/.config),)
include ../../../../linux-2.6.30/.config
else
include $(DIR_LINUX)/.config
endif

ifeq ($(wildcard $(DIR_USERS)/.config),)
include ../../../.config
else
include $(DIR_USERS)/.config
endif

#------------------------------------------------------------------------------
ifdef CONFIG_RTL_8198_AP_ROOT
CONFIG_RTL_AP = CONFIG_RTL_8198_AP_ROOT
endif

ifdef CONFIG_RTL_8197D_AP
CONFIG_RTL_AP = CONFIG_RTL_8197D_AP
endif

ifdef CONFIG_RTL_AP
AP=1
SKUTAG=ap
else
GW=1
SKUTAG=gw
endif

#------------------------------------------------------------------------------
COMPWEB=../../tools/compweb

#------------------------------------------------------------------------------
.PHONY: clean all

#------------------------------------------------------------------------------
#Record which files need not include
EXCLUDE_FILES =
EXCLUDE_FILES += ! -path '*/.*'
EXCLUDE_FILES += ! -path '*/*.bak'
EXCLUDE_FILES += ! -name Makefile
EXCLUDE_FILES += ! -name www_files
EXCLUDE_FILES += ! -name www_files.tar.bz2
EXCLUDE_FILES += ! -name webpages.bin
EXCLUDE_FILES += ! -name skb_portfilter.htm ! -name skb_dhcp6s.htm ! -name skb_dnsv6.htm ! -name skb_syscmd.htm ! -name skb_wizard.htm
EXCLUDE_FILES += ! -name skb_ipfilter.htm ! -name skb_dnslist.htm ! -name skb_ip6_qos.htm ! -name skb_wlwps.htm ! -name skb_wlwds.htm
EXCLUDE_FILES += ! -name skb_portfilter6.htm ! -name skb_ipv6_basic.htm ! -name skb_opmode.htm ! -name skb_urlfilter.htm ! -name skb_wlwdsenp.htm
EXCLUDE_FILES += ! -name skb_ip6filter.htm ! -name skb_radvd.htm ! -name skb_route.htm ! -name skb_routetbl.htm ! -name skb_vlan_wan.htm
EXCLUDE_FILES += ! -name skb_wlan_schedule.htm ! -name skb_wlbandmode.htm ! -name skb_wlmeshproxy.htm ! -name skb_wlsch.htm ! -name skb_wlwdstbl.htm

#samba web support
ifneq ($(CONFIG_APP_SAMBA_WEB),y)
EXCLUDE_FILES += ! -name skb_administration.htm ! -name skb_disk.htm ! -name skb_storage_creategroup.htm ! -name skb_storage_createsharefolder.htm
EXCLUDE_FILES += ! -name skb_storage_createuser.htm ! -name skb_storage_editgroup.htm ! -name skb_storage_edituser.htm
endif

# routing support
ifneq ($(CONFIG_APP_ROUTED),y)
EXCLUDE_FILES += ! -name skb_route.htm ! -name skb_routetbl.htm
endif

# boa cgi support
ifneq ($(BOA_CGI_SUPPORT),y)
EXCLUDE_FILES += ! -name test.cgi ! -name nph-test.cgi
endif

#for 11s mesh
ifneq ($(CONFIG_RTL_MESH_SUPPORT),y)
EXCLUDE_FILES += ! -name skb_buffalo.htm ! -name skb_bull.htm ! -name skb_wlmesh.htm ! -name skb_wlmeshinfo.htm ! -name skb_wlmeshACL.htm
endif

ifneq ($(CONFIG_RTK_VLAN_SUPPORT),y)
#EXCLUDE_FILES += ! -name skb_vlan.htm
endif

ifneq ($(CONFIG_PCIE_POWER_SAVING),y)
EXCLUDE_FILES += ! -name skb_powerConsumption.htm ! -name skb_powerConsumption_data.htm ! -name powerConsumption_proc.sxsl
EXCLUDE_FILES += ! -name num-0.gif ! -name num-1.gif ! -name num-2.gif ! -name num-3.gif ! -name num-4.gif ! -name num-5.gif
EXCLUDE_FILES += ! -name num-6.gif ! -name num-7.gif ! -name num-8.gif ! -name num-9.gif ! -name dot.gif ! -name num-0.gif
EXCLUDE_FILES += ! -name skb_xml_data.js
endif

ifneq ($(CONFIG_RTL_ULINKER),y)
EXCLUDE_FILES += ! -name skb_ulinker_opmode.htm
endif

ifneq ($(CONFIG_HTTP_FILE_SERVER_SUPPORT),y)
EXCLUDE_FILES += ! -name skb_http_files.htm
EXCLUDE_FILES += ! -name skb_http_files.htm
EXCLUDE_FILES += ! -name skb_usb_conninfo.htm
EXCLUDE_FILES += ! -name skb_http_files_dir.htm
endif

ifneq ($(CONFIG_RTL_P2P_SUPPORT),y)
EXCLUDE_FILES += ! -name skb_wlp2p.htm ! -name skb_wlp2pscanlist.htm ! -name skb_wlp2pstate.htm ! -name skb_wlp2pwscconnect.htm ! -name skb_wlp2pwscsel.htm
endif

ifneq ($(CONFIG_APP_CTORRENT), y)
EXCLUDE_FILES += ! -name skb_bt.htm ! -name skb_btnewtorrent.htm ! -name skb_btclient.htm
endif

ifneq ($(CONFIG_APP_TRANSMISSION), y)
EXCLUDE_FILES += ! -name skb_transmission.htm
endif

#ifneq ($(CONFIG_RTL_P2P_SUPPORT),y)
#EXCLUDE_FILES += ! -name skb_wlwapiCertManagement.htm
#endif

ifneq ($(CONFIG_IPV6),y)
EXCLUDE_FILES += ! -name skb_dhcp6s.htm  ! -name skb_ipv6_basic.htm ! -name skb_ip6filter.htm ! -name skb_dnsv6.htm ! -name skb_ipv6tcpipwan.htm ! -name skb_radvd.htm ! -name skb_tunnel6.htm ! -name skb_ip6_qos.htm ! -name skb_portfilter6.htm ! -name skb_sub_menu_ipv6.htm
endif

ifeq ($(CONFIG_IPV6),y)
EXCLUDE_FILES += ! -name skb_ipfilter.htm ! -name skb_portfilter.htm ! -name skb_ip_qos.htm
endif

ifneq ($(CONFIG_RTL_802_1X_CLIENT_SUPPORT),y)
EXCLUDE_FILES += ! -name skb_rsCertInstall.htm
endif
ifneq ($(CONFIG_RTL_ETH_802DOT1X_SUPPORT),y)
EXCLUDE_FILES += ! -name skb_eth_dot1x.htm
endif
ifneq ($(CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT),y)
EXCLUDE_FILES += ! -name skb_ethdot1xCertInstall.htm
endif
#ifneq ($(CONFIG_APP_SNMP),y)
#EXCLUDE_FILES += ! -name skb_snmp.htm
#endif
ifneq ($(CONFIG_APP_DVSNMP),y)
EXCLUDE_FILES += ! -name skb_snmp.htm
endif
ifneq ($(CONFIG_HTTP_FILE_SERVER_SUPPORT),y)
EXCLUDE_FILES += ! -name skb_usb_fileinfo.htm
endif
ifeq ($(SKUTAG),ap)
EXCLUDE_FILES += ! -name skb_portfilter.htm ! -name skb_ipfilter.htm ! -name skb_macfilter.htm ! -name skb_portfw.htm ! -name skb_urlfilter.htm ! -name skb_dmz.htm ! -name skb_ip_qos.htm ! -name skb_tcpipwan.htm ! -name skb_ddns.htm ! -name skb_dos.htm ! -name skb_opmode.htm
endif
ifeq ($(CONFIG_RTL_WAPI_SUPPORT),y)
ifneq ($(CONFIG_RTL_WAPI_LOCAL_AS_SUPPORT),y)
EXCLUDE_FILES += ! -name skb_wlwapiCertManagement.htm ! -name  skb_wlwapiDistribute.htm
endif
else
EXCLUDE_FILES += ! -name skb_wlwapiCertManagement.htm ! -name  skb_wlwapiDistribute.htm ! -name skb_wlwapiRekey.htm ! -name  skb_wlwapiinstallcert.htm
endif

# 8198 and POCKET ROUTER support both wapi psk and wapi cert
# 8196C (not include POCKET ROUTER) only support wapi psk
ifeq ($(CONFIG_RTL_8196C_GW),y)
ifneq ($(CONFIG_POCKET_ROUTER_SUPPORT),y)
#EXCLUDE_FILES += ! -name skb_wlwapiCertManagement.htm ! -name  skb_wlwapiDistribute.htm ! -name  skb_wlwapiinstallcert.htm
EXCLUDE_FILES += ! -name skb_wlwapiCertManagement.htm ! -name  skb_wlwapiDistribute.htm
endif
endif

ifneq ($(CONFIG_APP_TR069),y)
EXCLUDE_FILES += ! -name skb_share.js ! -name skb_tr069config.htm
endif

ifeq ($(CONFIG_APP_RTK_VOIP),y)
	#EXCLUDE_FILES += ! -name skb_vlan.htm
	EXCLUDE_FILES += ! -name skb_route.htm ! -name skb_routetbl.htm
	EXCLUDE_FILES += ! -name skb_ip_qos.htm
endif
ifneq ($(CONFIG_RTK_VLAN_WAN_TAG_SUPPORT),y)
#EXCLUDE_FILES += ! -name skb_vlan_wan.htm
endif
ifneq ($(CONFIG_APP_CPU_UTILIZATION), y)
EXCLUDE_FILES += ! -name skb_cpuShow.htm ! -name right.gif ! -name left.gif
endif

ifeq ($(CONFIG_RTL_BT_CLIENT),y)
EXCLUDE_FILES += ! -name skb_btclient.htm ! -name skb_bt.htm ! -name skb_btnewtorrent.htm
endif

ifeq ($(CONFIG_APP_BOA_NEW_UI),y)
EXCLUDE_FILES += ! -path './new/*'
EXCLUDE_FILES += ! -path './graphics/topbar.gif'
EXCLUDE_FILES += ! -path './menu-images/*'
EXCLUDE_FILES += ! -name skb_title.htm ! -name skb_code.htm ! -name skb_menu_empty.html
EXCLUDE_FILES += ! -name skb_home_old.htm  ! -name style_old.css ! -name skb_mtmcode.js
else
EXCLUDE_FILES += ! -path './new/*'
EXCLUDE_FILES += ! -name skb_home_old.htm ! -name style_old.css
endif
#------------------------------------------------------------------------------
all:
	rm -f www_files www_files.tar.bz2 webpages.bin webpages.*
	rm -f voip*.asp voip*.js
ifeq ($(CONFIG_APP_RTK_VOIP),y)
	rm -f voip*.asp voip*.js
	cp $(VOIP_APP)/web/voip*.asp .
	cp $(VOIP_APP)/web/voip*.js .
	sed -i "s/goform/boafrm/g" voip*.asp
	sed -i "s/method=\"get\"/method=\"post\"/g" voip*.asp
else
	rm -f voip*.asp voip*.js
endif
ifeq ($(CONFIG_APP_BOA_NEW_UI),y)
	cp  skb_home.htm skb_home_old.htm
	cp  style.css style_old.css
	cp  -f ./new/* .
endif
	find ./ -type f $(EXCLUDE_FILES) -name "*.*" > www_files
ifdef CONFIG_RTL_WEBPAGES_IN_ROOTFS
	cat www_files | xargs tar jcvf www_files.tar.bz2
else
#	$(COMPWEB) signature www_files webpages.bin $(CV_SIGNATURE)
	$(COMPWEB) $(SKUTAG) www_files webpages.bin
endif

ifeq ($(CONFIG_APP_BOA_NEW_UI),y)
#recovery
	ls -h ./new/ | xargs rm -f
	cp  skb_home_old.htm skb_home.htm
	cp  style_old.css style.css
endif

clean:
	rm -f www_files www_files.tar.bz2 webpages.bin webpages.*
ifeq ($(CONFIG_APP_RTK_VOIP),y)
	rm -f voip*.asp voip*.js
endif

