#ifndef __PRMT_WANIPCONNECTION_C__
#define __PRMT_WANIPCONNECTION_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_wanipconnection.h"
#include "prmt_ethernetstats.h"
#include "prmt_stats.h"
#include "prmt_portmapping.h"
#include "bcm_param_api.h"

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tWANIPConnection[] = {
	/*(name,						type,			flag,					accesslist,	getvalue,			 setvalue,			next_table,	sibling)*/
///	{"Enable",						eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"ConnectionStatus",			eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WANIPConnection, NULL,					NULL,		NULL},
///	{"PossibleConnectionTypes",		eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WANIPConnection, NULL,					NULL,		NULL},
///	{"ConnectionType",				eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"Name",						eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"Uptime",						eCWMP_tUINT,	CWMP_READ,				NULL,		get_WANIPConnection, NULL,					NULL,		NULL},
///	{"LastConnectionError",			eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WANIPConnection, NULL,					NULL,		NULL},
///	{"AutoDisconnectTime",			eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"IdleDisconnectTime",			eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"WarnDisconnectDelay",			eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"RSIPAvailable",				eCWMP_tBOOLEAN,	CWMP_READ,				NULL,		get_WANIPConnection, NULL,					NULL,		NULL},
///	{"NATEnabled",					eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
	{"AddressingType",				eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
	{"ExternalIPAddress",			eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
	{"SubnetMask",					eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
	{"DefaultGateway",				eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"DNSEnabled",					eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"DNSOverrideAllowed",			eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
	{"DNSServers",					eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"MaxMTUSize",					eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
	{"MACAddress",					eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WANIPConnection, NULL,					NULL,		NULL},
///	{"MACAddressOverride",			eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"RouteProtocolRx",				eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
//	{"PortMappingNumberOfEntries",  eCWMP_tUINT,	CWMP_READ,				NULL,		get_WANIPConnection, NULL,					NULL,		NULL},
//	{"PortMapping",					eCWMP_tOBJECT,	CWMP_WRITE|CWMP_READ,	NULL,		NULL,				PortMapObj,				NULL,		NULL},
///	{"ShapingRate",					eCWMP_tINT,		CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"ShapingBurstSize",			eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
///	{"Reset",						eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANIPConnection, set_WANIPConnection,	NULL,		NULL},
	{"Stats",						eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE,	NULL,		NULL,				 NULL,					tEthernetStats, NULL},
	{"",							eCWMP_tNONE,	0,						NULL,		NULL,				 NULL,					NULL,		NULL}
};

struct sCWMP_ENTITY tWANIPConTBL1[] = {
	/*(name,	type,			flag,	accesslist,	getvalue,	setvalue,	next_table,			sibling)*/
	{"1", 		eCWMP_tOBJECT,	0,		NULL,		NULL,		NULL,		tWANIPConnection,	NULL},
	{"",		eCWMP_tNONE,	0,		NULL,		NULL,		NULL,		NULL,				NULL}
};

int get_WANIPConnection(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[128] = {0};

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if (!nv_strcmp(lastname, "Enable")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "ConnectionStatus")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "PossibleConnectionTypes")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "ConnectionType")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "Name")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "Uptime")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "LastConnectionError")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "AutoDisconnectTime")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "IdleDisconnectTime")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "WarnDisconnectDelay")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "RSIPAvailable")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "NATEnabled")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "AddressingType")) {
		if (get_wan_proto_mo(buf, sizeof(buf)))
			*data = strdup( (char*)buf );
		else
			return ERR_9002;

	} else if (!nv_strcmp(lastname, "ExternalIPAddress")) {
		if (get_wanip(buf, sizeof(buf)))
			*data = strdup( (char*)buf );
		else
			return ERR_9002;

	} else if (!nv_strcmp(lastname, "SubnetMask")) {
		if (get_wanmask(buf, sizeof(buf)))
			*data = strdup( (char*)buf );
		else
			return ERR_9002;

	} else if (!nv_strcmp(lastname, "DefaultGateway")) {
		if (get_gateway(buf, sizeof(buf)))
			*data = strdup((char *)buf);
		else
			return ERR_9002;

	} else if (!nv_strcmp(lastname, "DNSEnabled")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "DNSOverrideAllowed")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "DNSServers")) {
		char strServer[2][20];

		get_dns(strServer[0], sizeof(strServer[0]),1, 0);
		get_dns(strServer[1], sizeof(strServer[1]),2, 0);
		snprintf(buf, sizeof(buf), "%s,%s", strServer[0], strServer[1]);
//		snprintf(buf, sizeof(buf), "%s", strServer[0]);
		*data = strdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "MaxMTUSize")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "MACAddress")) {
		get_wan_macaddr(buf, sizeof(buf), UPPER);
		*data = strdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "MACAddressOverride")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "RouteProtocolRx")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "PortMappingNumberOfEntries")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "ShapingRate")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "ShapingBurstSize")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "Reset")) {
		empty_data(*type, data);
	} else
		return ERR_9005;

	return 0;
}
int set_WANIPConnection(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char    *lastname = entity->name;
	char    *buf=data;
	int     len=0;

	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;

	if (!nv_strcmp(lastname, "Enable")) {
	} else if (!nv_strcmp(lastname, "ConnectionType")) {
	} else if (!nv_strcmp(lastname, "Name")) {
	} else if (!nv_strcmp(lastname, "AutoDisconnectTime")) {
	} else if (!nv_strcmp(lastname, "IdleDisconnectTime")) {
	} else if (!nv_strcmp(lastname, "WarnDisconnectDelay")) {
	} else if (!nv_strcmp(lastname, "NATEnabled")) {
	} else if (!nv_strcmp(lastname, "AddressingType")) {
		if (set_wan_proto(buf))
			return 1;
		else
			return ERR_9007;

	} else if (!nv_strcmp(lastname, "ExternalIPAddress")) {
		if (set_wanip(buf))
			return 1;
		else
			return ERR_9007;

	} else if (!nv_strcmp(lastname, "SubnetMask")) {
		if (set_wanmask(buf))
			return 1;
		else
			return ERR_9007;

	} else if (!nv_strcmp(lastname, "DefaultGateway")) {
		if (set_gateway(buf))
			return 1;
		else
			return ERR_9007;

	} else if (!nv_strcmp(lastname, "DNSEnabled")) {
	} else if (!nv_strcmp(lastname, "DNSOverrideAllowed")) {
	} else if (!nv_strcmp(lastname, "DNSServers")) {
		if( buf ) len = STRLEN( buf );

		if (len > 0) {
			if (set_dns(buf) == -1)
				return ERR_9007;
		}

	} else if (!nv_strcmp(lastname, "MaxMTUSize")) {
	} else if (!nv_strcmp(lastname, "MACAddress")) {
	} else if (!nv_strcmp(lastname, "MACAddressOverride")) {
	} else if (!nv_strcmp(lastname, "RouteProtocolRx")) {
	} else if (!nv_strcmp(lastname, "ShapingRate")) {
	} else if (!nv_strcmp(lastname, "ShapingBurstSize")) {
	} else if (!nv_strcmp(lastname, "Reset")) {
	} else
		return ERR_9005;

	return 1;
}
#endif /* __PRMT_WANIPCONNECTION_C__ */
