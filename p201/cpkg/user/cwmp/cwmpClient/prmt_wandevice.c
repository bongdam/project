#ifndef __PRMT_WANDEVICE_C__
#define __PRMT_WANDEVICE_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_wandevice.h"
#include "prmt_wanconnectiondevice.h"
#include "prmt_wancommoninterfaceconf.h" 
#include "prmt_wanethernetinterfaceconf.h"

struct sCWMP_ENTITY tWANCONTBL[] = {
	/*(name,							type,			flag,		accesslist,	getvalue,		setvalue,	next_table,				sibling)*/
	{"WANConnectionNumberOfEntries",	eCWMP_tUINT,	CWMP_READ,	NULL,		get_WANDevice,	NULL,		NULL,						NULL},
	{"WANConnectionDevice",				eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,			NULL,	 	tWANConnectionDevice,		NULL},
///	{"WANCommonInterfaceConfig",		eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,			NULL,		tWANCommonInterfaceConf,	NULL},
	{"WANEthernetInterfaceConfig",		eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,			NULL,		tWANEthernetInterfaceConf,	NULL},
	{"",								eCWMP_tNONE,	0, 			NULL, 		NULL, 			NULL,	 	NULL,						NULL}
};

struct sCWMP_ENTITY tWANDevice[] = {
	/*(name,	type,			flag,	 	accesslist,	getvalue,		setvalue,	next_table,	sibling)*/
	{"1",		eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,			NULL, 		tWANCONTBL,	NULL},
	{"",		eCWMP_tNONE,	0,			NULL,		NULL,			NULL,		NULL,		NULL}
};


int get_WANDevice(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if (!nv_strcmp(lastname, "WANConnectionNumberOfEntries")) {
		*data = uintdup(1);
	} else
		return ERR_9005;

	return 0;
}

#endif /* __PRMT_WANDEVICE_C__ */

