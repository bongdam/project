#ifndef __PRMT_WANETHERNETLINKCONFIG_C__
#define __PRMT_WANETHERNETLINKCONFIG_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_wanethernetlinkconfig.h"

struct s_WANEthernetLinkConfig {
	char					EthernetLinkStatus;
};

struct sCWMP_ENTITY tWANEthernetLinkConf[] = {
	/*(name,							type,							flag,	 					accesslist,	getvalue,								setvalue,		next_table,	sibling)*/
	{"EthernetLinkStatus",	eCWMP_tSTRING,		CWMP_READ,		NULL,			get_WANEthernetLinkConf,	NULL,			NULL,			NULL},
	{"",									eCWMP_tNONE,			0,							NULL,			NULL,								NULL,			NULL,			NULL}
};

int get_WANEthernetLinkConf(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	unsigned char buf[256] = {0};

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "EthernetLinkStatus" )==0 )
	{
		cwmp_cfg_get(CWMP_WAN_ETHERNET_LINK_STATUS, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else{
		return ERR_9005;
	}

	return 0;
}
#endif /* __PRMT_WANETHERNETLINKCONFIG_C__ */
