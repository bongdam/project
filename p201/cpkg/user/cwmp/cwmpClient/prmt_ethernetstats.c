#ifndef __PRMT_ETHERNETSTATS_C__
#define __PRMT_ETHERNETSTATS_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "bcm_param_api.h"
#include "prmt_ethernetstats.h"

#if 0
struct s_EthernetStats {
	unsigned int	EthernetBytesSent;
	unsigned int	EthernetBytesReceived;
	unsigned int	EthernetPacketsSent;
	unsigned int	EthernetPacketsReceived;
	unsigned int	EthernetErrorsSent;
	unsigned int	EthernetErrorsReceived;
	unsigned int	EthernetUnicastPacketsSent;
	unsigned int	EthernetUnicastPacketsReceived;
	unsigned int	EthernetDiscardPacketsSent;
	unsigned int	EthernetDiscardPacketsReceived;
	unsigned int	EthernetMulticastPacketsSent;
	unsigned int	EthernetMulticastPacketsReceived;
	unsigned int	EthernetBroadcastPacketsSent;
	unsigned int	EthernetBroadcastPacketsReceived;
	unsigned int	EthernetUnknownProtoPacketsReceived;
};
#endif

struct sCWMP_ENTITY tEthernetStats[] = {
	/*(name,															type,					flag,	 				accesslist,	getvalue,					setvalue,	next_table,	sibling)*/
	{"EthernetBytesSent",					eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetBytesReceived",				eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetPacketsSent",					eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetPacketsReceived",				eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetErrorsSent",					eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetErrorsReceived",				eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetUnicastPacketsSent",			eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetUnicastPacketsReceived",		eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetDiscardPacketsSent",			eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetDiscardPacketsReceived",		eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetMulticastPacketsSent",		eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetMulticastPacketsReceived",	eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetBroadcastPacketsSent",		eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetBroadcastPacketsReceived",	eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"EthernetUnknownProtoPacketsReceived",	eCWMP_tUINT,	CWMP_READ,	NULL,			get_EthernetStats,	NULL,		NULL,			NULL},
	{"",									eCWMP_tNONE,	0,			NULL,			NULL,				NULL,		NULL,			NULL}
};

extern char *get_wan_name(void);

int get_EthernetStats(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char	ifname[8];
	unsigned int res = 0;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	strncpy(ifname, get_wan_name(), sizeof(ifname));

	if (!nv_strcmp(lastname, "EthernetBytesSent")) {
		res = get_traffic(ifname, 9);
		*data = uintdup(res);

	} else if (!nv_strcmp(lastname, "EthernetBytesReceived")) {
		res = get_traffic(ifname, 1);
		*data = uintdup(res);

	} else if (!nv_strcmp(lastname, "EthernetPacketsSent")) {
		res = get_traffic(ifname, 10);
		*data = uintdup(res);

	} else if (!nv_strcmp(lastname, "EthernetPacketsReceived")) {
		res = get_traffic(ifname, 2);
		*data = uintdup(res);

	} else if (!nv_strcmp(lastname, "EthernetErrorsSent")) {
		res = get_traffic(ifname, 11);
		*data = uintdup(res);

	} else if (!nv_strcmp(lastname, "EthernetErrorsReceived")) {
		res = get_traffic(ifname, 3);
		*data = uintdup(res);

	} else if (!nv_strcmp(lastname, "EthernetUnicastPacketsSent")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "EthernetUnicastPacketsReceived")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "EthernetDiscardPacketsSent")) {
		res = get_traffic(ifname, 12);
		*data = uintdup(res);

	} else if (!nv_strcmp(lastname, "EthernetDiscardPacketsReceived")) {
		res = get_traffic(ifname, 4);
		*data = uintdup(res);

	} else if (!nv_strcmp(lastname, "EthernetMulticastPacketsSent")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "EthernetMulticastPacketsReceived")) {
		res = get_traffic(ifname, 8);
		*data = uintdup(res);

	} else if (!nv_strcmp(lastname, "EthernetBroadcastPacketsSent")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "EthernetBroadcastPacketsReceived")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "EthernetUnknownProtoPacketsReceived")) {
		empty_data(*type, data);
	} else
		return ERR_9005;

	return 0;
}
#endif /* __PRMT_ETHERNETSTATS_C__ */
