#ifndef __PRMT_LANINTERFACE_C__
#define __PRMT_LANINTERFACE_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_laninterface.h"

struct s_LanInterface {
	unsigned int LANEthernetInterfaceNumberOfEntries;
	unsigned int LANWLANConfigurationNumberOfEntries;
};

struct sCWMP_ENTITY tLanInterface[] = {
	/*(name,								type,				flag,	 	accesslist,	getvalue,			setvalue,	next_table,	sibling)*/
	{"LANEthernetInterfaceNumberOfEntries",	eCWMP_tUINT,		CWMP_READ,	NULL,		get_LanInterface,	NULL,		NULL,		NULL},
	{"LANUSBInterfaceNumberOfEntries",		eCWMP_tUINT,		CWMP_READ,	NULL,		get_LanInterface,	NULL,		NULL,		NULL},
	{"LANWLANConfigurationNumberOfEntries",	eCWMP_tUINT,		CWMP_READ,	NULL,		get_LanInterface,	NULL,		NULL,		NULL},
	{"",									eCWMP_tNONE,		0,			NULL,		NULL,				NULL,		NULL,		NULL}
};

int get_LanInterface(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	unsigned char buf[256] = {0};

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "LANEthernetInterfaceNumberOfEntries" )==0 )
	{
		//cwmp_cfg_get(CWMP_LAN_ETHERNET_INTERFACE_NUM_ENTRIES, (void*)buf, sizeof(buf));
		*data = uintdup( (unsigned int)buf );
	}else if( nv_strcmp( lastname, "LANUSBInterfaceNumberOfEntries" )==0 )
	{
		*data = uintdup((unsigned int)buf);
	}else if( nv_strcmp( lastname, "LANWLANConfigurationNumberOfEntries" )==0 )
	{
		//cwmp_cfg_get(CWMP_LAN_WLAN_CONF_NUM_ENTRIES, (void*)buf, sizeof(buf));
		*data = uintdup( (unsigned int)buf );
	}else{
		return ERR_9005;
	}

	return 0;
}

#endif /* __PRMT_USERINTERFACE_C__ */

