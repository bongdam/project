#ifndef __PRMT_LAYER3_FORWARDING_C__
#define __PRMT_LAYER3_FORWARDING_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_layer3_forwarding.h"
#include "prmt_forwarding.h"
#include <sys/sysinfo.h>

struct s_Layer3_Forwarding {
	char DefaultConnectionService[256];
	unsigned int ForwardNumberOfEntries;
};

struct sCWMP_ENTITY tLayer3Forwarding[] =
{
	/*(name,						type,				flag,	 				accesslist,	getvalue,				setvalue,				next_table,	sibling)*/
	{"DefaultConnectionService",	eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_Layer3_Forwarding,	set_Layer3_Forwarding,	NULL,		NULL},
	{"ForwardNumberOfEntries",		eCWMP_tUINT,		CWMP_READ,				NULL,		get_Layer3_Forwarding,	NULL,					NULL,		NULL},
	{"Forwarding",					eCWMP_tOBJECT,		CWMP_READ|CWMP_WRITE,	NULL,		NULL,					tSRouteObj,				NULL,		NULL},
	{"",							eCWMP_tNONE,		0,						NULL,		NULL,					NULL,					NULL,		NULL}
};

int get_Layer3_Forwarding(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[128] = {0, };

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "DefaultConnectionService" )==0 )
	{
		//cwmp_cfg_get(CWMP_DEFAULT_CONN_SERVICE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "ForwardNumberOfEntries" )==0 )
	{
		nvram_safe_get_r("STATICROUTE_TBL_NUM", buf, sizeof(buf));
		*data = uintdup(strtoul(buf, NULL, 10));
	}else{
		return ERR_9005;
	}

	return 0;
}

int set_Layer3_Forwarding(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
	char *buf = data;
	int len = 0;
	
	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1; 
	if( entity->type!=type ) return ERR_9006;

	if( nv_strcmp( lastname, "DefaultConnectionService" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len == 0 )
			cwmp_cfg_set( CWMP_DEFAULT_CONN_SERVICE, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_DEFAULT_CONN_SERVICE, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;
	} else 
		return ERR_9005;

	return 0;
}

#endif /* __PRMT_LAYER3_FORWARDING_C__ */

