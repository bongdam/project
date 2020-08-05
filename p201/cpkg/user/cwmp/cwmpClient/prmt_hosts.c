#ifndef __PRMT_HOSTS_C__
#define __PRMT_HOSTS_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_hosts.h"
#include "prmt_host.h"
#include "bcm_param_api.h"

struct s_Hosts {
	unsigned int HostNumberOfEntries;
};

struct sCWMP_ENTITY tHosts[] = {
	/*(name,					type,			flag,	 				accesslist,	getvalue,		setvalue,	next_table,	    sibling)*/
	{"HostNumberOfEntries",		eCWMP_tUINT,	CWMP_READ,				NULL,		get_Hosts,		NULL,		NULL,			NULL},
	{"Host",					eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE,	NULL,		NULL,			HostObj,	NULL,			NULL},
	{"",						eCWMP_tNONE,	0,						NULL,		NULL,			NULL,		NULL,			NULL}
};

int get_Hosts(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	struct ip_tbl_t		List[64];

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "HostNumberOfEntries" )==0 )
	{
		if (IS_BRIDGE_MODE)
			*data = uintdup(0);
		else
			*data = uintdup(get_device_info(List));
	} else {
		return ERR_9005;
	}

	return 0;
}
#endif /* __PRMT_HOSTS_C__ */
