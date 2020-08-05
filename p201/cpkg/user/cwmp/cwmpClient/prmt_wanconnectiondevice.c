#ifndef __PRMT_WANCONNECTIONDEVICE_C__
#define __PRMT_WANCONNECTIONDEVICE_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_wanconnectiondevice.h"
#include "prmt_wanipconnection.h"

struct s_WANConnectionDevice {
	unsigned int	WANIPConnectionNumberOfEntries;
};

struct sCWMP_ENTITY tWANConTBL[] = {
	/*(name,			type,			flag,	accesslist,	getvalue,	setvalue,	next_table,		sibling)*/
	{"WANIPConnection",	eCWMP_tOBJECT,	0,		NULL,		NULL,		NULL,		tWANIPConTBL1,	NULL},
	{"",				eCWMP_tNONE,	0,		NULL,		NULL,		NULL,		NULL,			NULL}
};

struct sCWMP_ENTITY tWANConnectionDevice[] = {
	/*(name,							type,			flag,	 	accesslist,	getvalue,					setvalue,	next_table,	sibling)*/
	{"WANIPConnectionNumberOfEntries",	eCWMP_tUINT,	CWMP_READ,	NULL,		get_WANConnectionDevice,	NULL,		NULL,		NULL},
	{"1",								eCWMP_tOBJECT,	0,			NULL,		NULL,						NULL,		tWANConTBL,	NULL},
	{"",								eCWMP_tNONE,	0,			NULL,		NULL,						NULL,		NULL,		NULL}
};
int get_WANConnectionDevice(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if (!nv_strcmp(lastname, "WANIPConnectionNumberOfEntries")) {
		*data = uintdup(1);

	} else
		return ERR_9005;

	return 0;
}
#endif /* __PRMT_WANCONNECTIONDEVICE_C__ */
