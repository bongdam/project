#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/klog.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <syslog.h>
#include <bcmnvram.h>
#include "apmib.h"
#include "holepunch_vman.h"


nv_variable *nv_rename_value()
{
    return (&nv_name_tbl[0]);
}

dv_variable *dv_rename_value()
{
	return (&dv_name_tbl[0]);
}

char *holepunch_dv_get_value(char *name)
{
	dv_variable *v;
	char *value=NULL;

	for (v=dv_rename_value(); v->name; v++) {
		if (!strcmp(v->name, name)) {
			value = nvram_get(v->dv_name);
			break;
		}
	}
	return value;
}

void holepunch_dv_set_value(char *name, char *value)
{
	dv_variable *v;

	for (v=dv_rename_value(); v->name; v++) {
		if (!strcmp(v->name, name)) {
			nvram_set(v->dv_name, value);
			break;
		}
	}
}

char *holepunch_nv_get_value(char *name)
{
	nv_variable *v;
	char *value=NULL;

	for (v=nv_rename_value(); v->name; v++) {
		if (!strcmp(v->name, name)) {
			value =nvram_get(v->nv_name);
			break;
		}
	}
	return value;
}

void holepunch_nv_set_value(MIBS interface, char *value)
{
	int val;
	char *buf;

	val = atoi(value);
	switch(interface) {
		case wlan0_disable :
			wlan_interface_change(0, 0);
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			break;
		case wlan0_voip_disable :
			wlan_interface_change(0, 1);
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			break;
		case wlan0_t_wifi_disable :
			wlan_interface_change(0, 2);
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			break;
		case wlan0_anyway_disable :
			wlan_interface_change(0, 3);
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			break;
		case wlan0_ratelimit :
			wlan_interface_change(0, 0);
			apmib_set(MIB_WLAN_TX_RESTRICT, (void *)&val);
			apmib_set(MIB_WLAN_RX_RESTRICT, (void *)&val);
			break;
		case wlan0_voip_ratelimit :
			wlan_interface_change(0, 1);
			apmib_set(MIB_WLAN_TX_RESTRICT, (void *)&val);
			apmib_set(MIB_WLAN_RX_RESTRICT, (void *)&val);
			break;
		case wlan0_t_wifi_ratelimit :
			wlan_interface_change(0, 2);
			apmib_set(MIB_WLAN_TX_RESTRICT, (void *)&val);
			apmib_set(MIB_WLAN_RX_RESTRICT, (void *)&val);
			break;
		case wlan0_anyway_ratelimit :
			wlan_interface_change(0, 3);
			apmib_set(MIB_WLAN_TX_RESTRICT, (void *)&val);
			apmib_set(MIB_WLAN_RX_RESTRICT, (void *)&val);
			break;
		case wlan1_disable :
			wlan_interface_change(1, 0);
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			buf = nvram_get("x_handover_enable")? :"1";
			if(atoi(buf) == 1) {
				wlan_interface_change(0, 4);					//handover 5G_wlan
				apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			}
			break;
		case wlan1_voip_disable :
			wlan_interface_change(1, 1);
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			break;
		case wlan1_t_wifi_disable :
			wlan_interface_change(1, 2);
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			break;
		case wlan1_multi_disable :
			wlan_interface_change(1, 4);
			apmib_set(MIB_WLAN_WLAN_DISABLED, (void *)&val);
			break;
		case wlan1_ratelimit :
			wlan_interface_change(1, 0);
			apmib_set(MIB_WLAN_TX_RESTRICT, (void *)&val);
			apmib_set(MIB_WLAN_RX_RESTRICT, (void *)&val);
			buf = nvram_get("x_handover_enable")? :"1";
			if(atoi(buf) == 1) {
				wlan_interface_change(0, 4);					//handover 5G_wlan
				apmib_set(MIB_WLAN_TX_RESTRICT, (void *)&val);
				apmib_set(MIB_WLAN_RX_RESTRICT, (void *)&val);
			}
			break;
		case wlan1_voip_ratelimit :
			wlan_interface_change(1, 1);
			apmib_set(MIB_WLAN_TX_RESTRICT, (void *)&val);
			apmib_set(MIB_WLAN_RX_RESTRICT, (void *)&val);
			break;
		case wlan1_t_wifi_ratelimit :
			wlan_interface_change(1, 2);
			apmib_set(MIB_WLAN_TX_RESTRICT, (void *)&val);
			apmib_set(MIB_WLAN_RX_RESTRICT, (void *)&val);
			break;
		case wlan1_multi_ratelimit :
			wlan_interface_change(1, 4);
			apmib_set(MIB_WLAN_TX_RESTRICT, (void *)&val);
			apmib_set(MIB_WLAN_RX_RESTRICT, (void *)&val);
			break;
		default :
			break;
	}
	apmib_recov_wlanIdx();
}

void save_change_status()
{
	nvram_commit();
}