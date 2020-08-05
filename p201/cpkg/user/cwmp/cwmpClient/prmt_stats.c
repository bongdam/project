#ifndef __PRMT_STATS_C__
#define __PRMT_STATS_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "bcm_param_api.h"
#include "prmt_stats.h"
#include <ifport_counter.h>

struct sCWMP_ENTITY tStats[] = {
	/*(name,												type,					flag,	 				accesslist,	getvalue,		setvalue,	next_table,	sibling)*/
	{"BytesSent",					eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"BytesReceived",				eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"PacketsSent",					eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"PacketsReceived",				eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"ErrorsSent",					eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"ErrorsReceived",				eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"UnicastPacketsSent",			eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"UnicastPacketsReceived",		eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"DiscardPacketsSent",			eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"DiscardPacketsReceived",		eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"MulticastPacketsSent",		eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"MulticastPacketsReceived",	eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"BroadcastPacketsSent",		eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"BroadcastPacketsReceived",	eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"UnknownProtoPacketsReceived",	eCWMP_tUINT,	CWMP_READ,	NULL,			get_Stats,	NULL,		NULL,			NULL},
	{"",							eCWMP_tNONE,	0,			NULL,			NULL,		NULL,		NULL,			NULL}
};

#define STAT_LAN  1
#define STAT_WLAN 2
#define STAT_WAN  3

#define WAN_PORT_NUM  4	// GAPD-7100 specific
#define LAN0_PORT_NUM 0	// GAPD-7100 specific


int get_Stats(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	unsigned int res = 0;
	char ifname[16] = "", *ptr;
	int pn = 0;
	int stat_type;
	struct ifport_counter_t c;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	if ((ptr = strstr(name, "LANEthernetInterfaceConfig."))!=NULL) {
		char *deli = "LANEthernetInterfaceConfig.";

		if (STRLEN(ptr) > STRLEN(deli)) {
			ptr += STRLEN(deli);
			pn = atoi(ptr);
		}
		stat_type = STAT_LAN;
	} else if ((ptr = strstr(name, "WLANConfiguration."))!=NULL) {
		char *deli="WLANConfiguration.";
		int idx=0, wl_idx, wl_subidx;

		if (STRLEN(ptr)>STRLEN(deli)) {
			ptr += STRLEN(deli);
			idx = atoi(ptr);

			if (idx <= 0 || idx >MAX_WLAN)
				return ERR_9005;

			get_wlan_idxes(idx, &wl_idx, &wl_subidx);
			get_wlan_ifname_from_idx(ifname, sizeof(ifname), wl_idx, wl_subidx);
			stat_type = STAT_WLAN;
		} else
			return ERR_9005;
	} else {
		stat_type = STAT_WAN;
	}

	*type = entity->type;
	*data = NULL;

	if (stat_type == STAT_WLAN) {
		res = ifport_counter(ifname, 0, &c);
	} else if (stat_type == STAT_WAN) {
		res = ifport_counter(NULL, WAN_PORT_NUM, &c);
	} else {
		res = ifport_counter(NULL, (pn-1) + LAN0_PORT_NUM, &c);
	}
	// I ignore ret, because all 0 returned on error case.

	if( nv_strcmp(lastname, "BytesSent" )==0 )
	{
		if (IS_BRIDGE_MODE && stat_type == STAT_WAN)    //APACRTL-340
			*data = uintdup(0);
		else
			*data = uintdup((unsigned int) c.tx_bytes);
	}else if( nv_strcmp( lastname, "BytesReceived")==0 )
	{
		if (IS_BRIDGE_MODE && stat_type == STAT_WAN)    //APACRTL-340
			*data = uintdup(0);
		else
			*data = uintdup((unsigned int) c.rx_bytes);
	}else if( nv_strcmp( lastname, "PacketsSent")==0 )
	{
		*data = uintdup( c.tx_upkts + c.tx_mpkts );
	}else if( nv_strcmp( lastname, "PacketsReceived")==0 )
	{
		*data = uintdup( c.rx_upkts + c.rx_mpkts );
	}else if( nv_strcmp( lastname, "ErrorsSent")==0 )
	{
		*data = uintdup( c.tx_errors );
	}else if( nv_strcmp( lastname, "ErrorsReceived")==0 )
	{
		*data = uintdup( c.rx_errors );
	}else if( nv_strcmp( lastname, "UnicastPacketsSent")==0 )
	{
		*data = uintdup( c.tx_upkts );
	}else if( nv_strcmp( lastname, "UnicastPacketsReceived")==0 )
	{
		*data = uintdup( c.rx_upkts );
	}else if( nv_strcmp( lastname, "DiscardPacketsSent")==0 )
	{
		*data = uintdup(0);
	}else if( nv_strcmp( lastname, "DiscardPacketsReceived")==0 )
	{
		*data = uintdup(0);
	}else if( nv_strcmp( lastname, "MulticastPacketsSent")==0 )
	{
		*data = uintdup(0);
	}else if( nv_strcmp( lastname, "MulticastPacketsReceived")==0 )
	{
		*data = uintdup(0);
	}else if( nv_strcmp( lastname, "BroadcastPacketsSent")==0 )
	{
		*data = uintdup(0);
	}else if( nv_strcmp( lastname, "BroadcastPacketsReceived")==0 )
	{
		*data = uintdup(0);
	}else if( nv_strcmp( lastname, "UnknownProtoPacketsReceived")==0 )
	{
		*data = uintdup(0);
	}else{
		return ERR_9005;
	}
	return 0;
}
#endif /* __PRMT_STATS_C__ */
