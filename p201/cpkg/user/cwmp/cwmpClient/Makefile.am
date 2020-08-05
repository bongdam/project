####### This is the input file for automake, which will generate Makefile.in ##########
## not a GNU package. You can remove this line, if
## you have all needed files, that a GNU package needs
AUTOMAKE_OPTIONS = foreign 1.4
#ACLOCAL_AMFLAGS = -I m4

CFLAGS += $(WLAN_ComponentIncPath)
noinst_PROGRAMS=cwmpsslClient

SOAPHEADER=cwmp.h

GSOAP_DIR = ../libgsoap/soapcpp2
GSOAP_PLUGIN_DIR = $(GSOAP_DIR)/plugin
PARAMETER_SOURCES = parameter_api.h parameter_api.c cwmplib.c \
	cwmp_download.c \
	cwmp_notify.h cwmp_notify.c \
	prmt_igd.h prmt_igd.c \
	prmt_deviceinfo.h prmt_deviceinfo.c \
	prmt_mngmtserver.h prmt_mngmtserver.c \
	prmt_objsample.h prmt_objsample.c	\
	prmt_timeinfo.h prmt_timeinfo.c		\
	prmt_laninterface.h prmt_laninterface.c	\
	prmt_manageable_device.h prmt_manageable_device.c	\
	prmt_forwarding.h prmt_forwarding.c	\
	prmt_lanhostconfmngmt.h prmt_lanhostconfmngmt.c	\
	prmt_lanethernetinterfaceconf.h prmt_lanethernetinterfaceconf.c	\
	prmt_wlanconf.h prmt_wlanconf.c	\
	prmt_hosts.h prmt_hosts.c	\
	prmt_wancommoninterfaceconf.h prmt_wancommoninterfaceconf.c	\
	prmt_wanethernetinterfaceconf.h prmt_wanethernetinterfaceconf.c	\
	prmt_wanconnectiondevice.h prmt_wanconnectiondevice.c	\
	prmt_wlan.h prmt_wlan.c	\
	prmt_queuemngmt.h prmt_queuemngmt.c	\
	prmt_ipinterface.h prmt_ipinterface.c	\
	prmt_stats.h prmt_stats.c	\
	prmt_ethernetstats.h prmt_ethernetstats.c	\
	prmt_wps.h prmt_wps.c	\
	prmt_connection.h prmt_connection.c	\
	prmt_wanethernetlinkconfig.h prmt_wanethernetlinkconfig.c	\
	prmt_associateddevice.h prmt_associateddevice.c	\
	prmt_wanipconnection.h prmt_wanipconnection.c	\
	prmt_vlan.h prmt_vlan.c	\
	prmt_portmapping.h prmt_portmapping.c	\
	prmt_host.h prmt_host.c	\
	prmt_layer3_forwarding.h prmt_layer3_forwarding.c \
	prmt_landevice.h prmt_landevice.c \
	prmt_vendor_config_file.h prmt_vendor_config_file.c \
	prmt_bridge.h prmt_bridge.c \
	prmt_staticlease.h prmt_staticlease.c \
	prmt_wandevice.h prmt_wandevice.c

PLUGIN_SOURCES = $(GSOAP_PLUGIN_DIR)/smdevp.h $(GSOAP_PLUGIN_DIR)/smdevp.c \
	$(GSOAP_PLUGIN_DIR)/httpda.h $(GSOAP_PLUGIN_DIR)/httpda.c \
	$(GSOAP_PLUGIN_DIR)/md5evp.h $(GSOAP_PLUGIN_DIR)/md5evp.c \
	$(GSOAP_PLUGIN_DIR)/threads.h $(GSOAP_PLUGIN_DIR)/threads.c \
	stun.h stun.c \
	utf8_util.h utf8_util.c \
	tlog_printf.h tlog_printf.c \
	udp.h udp.c

CWMPCORE_CFLAGS=-Wall -DEMBED -DWITH_COOKIES -DCWMP_ENABLE_DIGEST -DWITH_UDP -I$(GSOAP_DIR)/include -I$(GSOAP_PLUGIN_DIR) -I$(SRCBASE)/public_func -I$(SRCBASE)/secd

#MTD_SOURCES = $(SRCBASE)/shared/bcmutils.c
COMMON_LDFLAGS = -L$(SRCBASE)/libytool -lytool -L$(SRCBASE)/furl -lfurl -L$(SRCBASE)/public_func -lpublicfunc -L$(SRCBASE)/secd -lsecc -L$(SRCBASE)/secd/secplus -lsecplus_ap -L../libgsoap -lgsoapssl
MTD_CFLAGS = -I$(SRCBASE)/include
MTD_LDFLAGS = -L$(SRCBASE)/shared -lshared
CFG_SOURCES = bcm_cfg_api.h bcm_cfg_api.c bcm_param_api.h bcm_param_api.c
CFG_CFLAGS = -I$(DIR_LINUX)/drivers/net/wireless/rtl8192cd
CFG_CFLAGS += -I$(DIR_USERS)/boa/apmib -I$(DIR_USERS)/boa/src
CFG_LDFLAGS = -L$(SRCBASE)/nvram -lnvram -L$(CPKG_USER)/ares -lares
PLUSIN_SOURCES = $(MTD_SOURCES) $(CFG_SOURCES)
#PLUSIN_SOURCES=$(CFG_SOURCES)
PLUGIN_LDFLAGS = $(COMMON_LDFLAGS) $(MTD_LDFLAGS) $(CFG_LDFLAGS)
PLUGIN_CFLAGS = $(MTD_CFLAGS) $(CFG_CFLAGS)
cwmpsslClient_SOURCES = $(SOAPHEADER) $(PLUGIN_SOURCES) $(PARAMETER_SOURCES) cwmpClient.c cwmpClientLib.c soapC.c $(PLUSIN_SOURCES)
cwmpsslClient_LDADD = $(CWMP_LDFLAGS) $(PLUGIN_LDFLAGS)
cwmpsslClient_CFLAGS = -DCWMP_ENABLE_SSL $(CWMP_CFLAGS) $(CWMPCORE_CFLAGS) $(PLUGIN_CFLAGS)
install-exec-hook:
	$(install_sh_PROGRAM) -t $(sbindir)/cwmpsslClient cwmpsslClient
	mkdir -p $(INSTALLDIR)/etc/cert
	install allcerts.pem $(INSTALLDIR)/etc/cert/allcerts.pem
	install Symantec-Root\(2048bits\).pem $(INSTALLDIR)/etc/cert/Symantec-Root\(2048bits\).pem
	ln -sf /etc/cert/Symantec-Root\(2048bits\).pem $(INSTALLDIR)/etc/cert/b204d74a.0
	install ThawteprimaryRootCA\(2048\).pem $(INSTALLDIR)/etc/cert/ThawteprimaryRootCA\(2048\).pem
	ln -sf /etc/cert/ThawteprimaryRootCA\(2048\).pem $(INSTALLDIR)/etc/cert/2e4eed3c.0
	install DigiCert\ Global\ Root\ G2.cer $(INSTALLDIR)/etc/cert/DigiCert\ Global\ Root\ G2.cer
	ln -sf /etc/cert/DigiCert\ Global\ Root\ G2.cer $(INSTALLDIR)/etc/cert/607986c7.0

# $(install_sh_PROGRAM) -t $(sbindir)/cwmpClient cwmpClient
################################################################################################################
## common defines for Makefiles for the gsoap samples
##
################################################################################################################

AM_CFLAGS = -D$(platform)
AM_CXXFLAGS = -D$(platform)
INCLUDES = -I$(GSOAP_DIR) -I$(GSOAP_DIR)/plugin
SOAP = $(GSOAP_DIR)/soapcpp2
SOAP_NS_DEF = ns.nsmap ns.wsdl
SOAP_H_FILES = soapH.h soapStub.h
SOAP_FLAGS = -I$(GSOAP_DIR)/import -L
SOAP_C_ALL = soapClient.c soapServer.c soapC.c
SOAP_NS = cwmp.nsmap cwmp.wsdl


################################################################################################################
## common Makefile rules for building the C - soap samples
##
################################################################################################################

SOAP_C_SRC=$(SOAP_C_ALL) $(SOAP_H_FILES) $(SOAP_NS)

$(SOAP_C_SRC) : $(SOAPHEADER)
	$(SOAP) -c $(SOAP_FLAGS) $<

BUILT_SOURCES=$(SOAP_C_SRC)
CLEANFILES=$(SOAP_C_SRC) *.req.xml *.res.xml *.wsdl *.nsmap *.xsd *Proxy\.h *~

