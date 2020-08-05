#ifndef __PRMT_CONNECTION_C__
#define __PRMT_CONNECTION_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_connection.h"

struct sCWMP_ENTITY tConnection[] = {
	/*(name,	type,			flag, 		accesslist,	getvalue,	setvalue,	next_table,	sibling)*/
	{"1",		eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tConnTBL,	NULL},	
	{"",		eCWMP_tNONE,	0,			NULL,		NULL,		NULL,		NULL,		NULL}
};

struct sCWMP_ENTITY tConnTBL[] = {
	/*(name,							type,			flag,	 	accesslist,	getvalue,		setvalue,	next_table,	sibling)*/
	{"ActiveConnectionDeviceContainer",	eCWMP_tSTRING,	CWMP_READ,	NULL,		get_Connection,	NULL,		NULL,		NULL},
	{"ActiveConnectionServiceID",		eCWMP_tSTRING,	CWMP_READ,	NULL,		get_Connection,	NULL,		NULL,		NULL},
	{"",								eCWMP_tNONE,	0,			NULL,		NULL,			NULL,		NULL,		NULL}
};

int get_Connection(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "ActiveConnectionDeviceContainer" )==0 )
	{
		*data = strdup("default" );
	}else if( nv_strcmp( lastname, "ActiveConnectionServiceID" )==0 )
	{
		*data = strdup("default" );
	}else{
		return ERR_9005;
	}

	return 0;
}
#endif /* __PRMT_CONNECTION_C__ */
