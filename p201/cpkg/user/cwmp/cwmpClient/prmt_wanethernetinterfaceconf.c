#ifndef __PRMT_WANETHERNETINTERFACECONF_C__
#define __PRMT_WANETHERNETINTERFACECONF_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_wanethernetinterfaceconf.h"
#include "prmt_stats.h"
#include "bcm_param_api.h"

typedef enum {en_false = 0, en_true = 1} boolean;
struct sCWMP_ENTITY tWANEthernetInterfaceConf[] = {
	/*(name,				type,			flag,					accesslist,	getvalue,						setvalue,							next_table,	sibling)*/
	{"Enable",				eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,	get_WANEthernetInterfaceConf,		set_WANEthernetInterfaceConf,		NULL,			NULL},
	{"Status",				eCWMP_tSTRING,	CWMP_READ,				NULL,	get_WANEthernetInterfaceConf,		NULL,								NULL,			NULL},
	{"MACAddress",			eCWMP_tSTRING,	CWMP_READ,				NULL,	get_WANEthernetInterfaceConf,		NULL,								NULL,			NULL},
	{"MaxBitRate",			eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,	get_WANEthernetInterfaceConf,		set_WANEthernetInterfaceConf,		NULL,			NULL},
	{"DuplexMode",			eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,	get_WANEthernetInterfaceConf,		set_WANEthernetInterfaceConf,		NULL,			NULL},
///	{"ShapingRate",			eCWMP_tINT,		CWMP_WRITE|CWMP_READ,	NULL,	get_WANEthernetInterfaceConf,		set_WANEthernetInterfaceConf,		NULL,			NULL},
///	{"ShapingBurstSize",	eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,	NULL,	get_WANEthernetInterfaceConf,		set_WANEthernetInterfaceConf,		NULL,			NULL},
///	{"Stats",				eCWMP_tOBJECT,	CWMP_READ,				NULL,	NULL,								NULL,								tStats,			NULL},
	{"",					eCWMP_tNONE,	0,						NULL,	NULL,								NULL,								NULL,			NULL}
};

int get_WANEthernetInterfaceConf(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char tmp[128] = {0, };

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if (!nv_strcmp(lastname, "Enable")) {
		*data = booldup(1);

	} else if (!nv_strcmp(lastname, "Status")) {
		*data = strdup( get_wan_link_conn_status() );

	} else if (!nv_strcmp(lastname, "MACAddress")) {
		get_wan_macaddr(tmp, sizeof(tmp), UPPER);
		*data = strdup(tmp);

	} else if (!nv_strcmp(lastname, "MaxBitRate")) {
		//APACRTL-522
		*data = strdup( get_wan_maxbitrate() );

	} else if (!nv_strcmp(lastname, "DuplexMode")) {
		//APACRTL-522
		*data = strdup( get_wan_duplex() );

	} else if (!nv_strcmp(lastname, "ShapingRate")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "ShapingBurstSize")) {
		empty_data(*type, data);
	} else
		return ERR_9005;

	return 0;
}
int set_WANEthernetInterfaceConf(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
	char *buf = data;
	int len = 0;
	
	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1; 
	if( entity->type!=type ) return ERR_9006;

	if (!nv_strcmp(lastname, "Enable")) {
	} else if (!nv_strcmp(lastname, "MaxBitRate")) {
	} else if (!nv_strcmp(lastname, "DuplexMode")) {
	} else if (!nv_strcmp(lastname, "ShapingRate")) {
	} else if (!nv_strcmp(lastname, "ShapingBurstSize")) {
	} else 
		return ERR_9005;
	
	return 0;
}
#endif /* __PRMT_WANETHERNETINTERFACECONF_C__ */

