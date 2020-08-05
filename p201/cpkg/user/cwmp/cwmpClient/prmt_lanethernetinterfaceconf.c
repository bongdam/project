#ifndef __PRMT_LANETHERNETINTERFACECONF_C__
#define __PRMT_LANETHERNETINTERFACECONF_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_lanethernetinterfaceconf.h"
#include "prmt_stats.h"
#include "bcm_param_api.h"

#ifndef MAX_LAN_PORT
#define MAX_LAN_PORT 4
#endif

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tLanEternetInterfaceConf[] = {
	/*(name,					type,				flag,	 				accesslist,	getvalue,						setvalue,						next_table,	sibling)*/
	{"Enable",						eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_LanEternetInterfaceConf,	set_LanEternetInterfaceConf,	NULL,		NULL},
	{"Status",						eCWMP_tSTRING,	CWMP_READ,				NULL,		get_LanEternetInterfaceConf,	NULL,							NULL,		NULL},
///	{"MACAddress",					eCWMP_tSTRING,	CWMP_READ,				NULL,		get_LanEternetInterfaceConf,	NULL,							NULL,		NULL},
///	{"MACAddressControlEnabled",	eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_LanEternetInterfaceConf,	set_LanEternetInterfaceConf,	NULL,		NULL},
	{"MaxBitRate",					eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_LanEternetInterfaceConf,	set_LanEternetInterfaceConf,	NULL,		NULL},
	{"DuplexMode",					eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_LanEternetInterfaceConf,	set_LanEternetInterfaceConf,	NULL,		NULL},
///	{"Name",						eCWMP_tSTRING,	CWMP_READ,				NULL,		get_LanEternetInterfaceConf,	NULL,							NULL,		NULL},
///TODO	{"Stats",						eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE,	NULL,		NULL,							NULL,							tStats,		NULL},
	{"",							eCWMP_tNONE,	0,						NULL,		NULL,							NULL,							NULL,		NULL}
};

struct sCWMP_ENTITY tLANETHINFMAP[] = {
	{"0",							eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE|CWMP_LNKLIST, NULL, NULL,						NULL,							tLanEternetInterfaceConf, NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

int LANETHINFObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	unsigned int i;
	switch(type) {
	case eCWMP_tINITOBJ:
	{
		int ret;
		struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;

		for(i=0; i < MAX_LAN_PORT; i++) {
			ret = create_Object(c, tLANETHINFMAP, sizeof(tLANETHINFMAP), 1, i+1);
		}
		add_objectNum(name, i);
		return 0;
	}
	case eCWMP_tADDOBJ:
		return 0;
	case eCWMP_tDELOBJ:
		return 0;
	case eCWMP_tUPDATEOBJ:
		return 0;
	default:
		break;
	}

	return -1;
}


int get_LanEternetInterfaceConf(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[256] = {0}, *ptr;
	int pn=0 ;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	snprintf(buf, sizeof(buf), "%s", name);
	ptr = strstr(buf, "LANEthernetInterfaceConfig.");
	if (ptr && STRLEN(ptr) > STRLEN("LANEthernetInterfaceConfig."))
		ptr += STRLEN("LANEthernetInterfaceConfig.");

	pn = atoi(ptr);

	if (pn < 1 || pn > MAX_LAN_PORT)
		return ERR_9005;

	if (!nv_strcmp(lastname, "Enable")) {
		*data = booldup(1);

	} else if (!nv_strcmp(lastname, "Status")) {
		*data = strdup(get_lan_link_conn_status(pn));

	} else if (!nv_strcmp(lastname, "MACAddress")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "MACAddressControlEnabled")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "MaxBitRate")) {
		*data = strdup(get_lan_maxbitrate(pn));

	} else if (!nv_strcmp(lastname, "DuplexMode")) {
		*data = strdup(get_lan_duplex(pn));

	} else if (!nv_strcmp(lastname, "Name")) {
		empty_data(*type, data);
	} else
		return ERR_9005;

	return 0;
}
int set_LanEternetInterfaceConf(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char    *lastname = entity->name;
	char    *val=data;
	char	buf[256], *ptr;
	int 	pn;

	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;

	snprintf(buf, sizeof(buf), "%s", name);

	ptr = strstr(buf, "LANEthernetInterfaceConfig.");
	if (ptr && STRLEN(ptr) > STRLEN("LANEthernetInterfaceConfig."))
		ptr += STRLEN("LANEthernetInterfaceConfig.");

	pn = atoi(ptr);

	if (pn < 1 || pn > MAX_LAN_PORT)
		return ERR_9007;

	if (!nv_strcmp(lastname, "Enable")) {
	} else if (!nv_strcmp(lastname, "MACAddressControlEnabled")) {
	} else if (!nv_strcmp(lastname, "MaxBitRate")) {
	} else if (!nv_strcmp(lastname, "DuplexMode")) {
	} else
		return ERR_9005;

	return 0;
}
#endif /* __PRMT_LANETHERNETINTERFACECONF_C__ */

