#ifndef __PRMT_FORWARDING_C__
#define __PRMT_FORWARDING_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>

#include "prmt_forwarding.h"

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tForwarding[] = {
	/*(name,				type,			flag,	 				accesslist,	getvalue,		setvalue,		next_table,	sibling)*/
	{"Enable",				eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_Forwarding,	set_Forwarding,	NULL,		NULL},
	{"DestIPAddress",		eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_Forwarding,	set_Forwarding,	NULL,		NULL},
	{"DestSubnetMask",		eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_Forwarding,	set_Forwarding,	NULL,		NULL},
	{"GatewayIPAddress",	eCWMP_tSTRING,	CWMP_WRITE|CWMP_READ,	NULL,		get_Forwarding,	set_Forwarding,	NULL,		NULL},
	{"",					eCWMP_tNONE,	0,						NULL,		NULL,			NULL,			NULL,		NULL}
};

struct sCWMP_ENTITY tRouteMAP[] = {
	{"0",                       eCWMP_tOBJECT,  CWMP_READ|CWMP_WRITE|CWMP_LNKLIST,  NULL,       NULL,               NULL,           tForwarding,  NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

int tSRouteObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	unsigned int i = 0;
	char t[16] = {0, };
	struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;

	switch(type) {
	case eCWMP_tINITOBJ:
	{
		int max = atoi(nvram_safe_get_r("STATICROUTE_TBL_NUM",t, sizeof(t)));
		int ret;

		for(i = 0; i < max; i++) {
			ret = create_Object(c, tRouteMAP, sizeof(tRouteMAP), 1, i+1);
			if (ret < 0)
				break;
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
int get_Forwarding(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	unsigned char buf[256] = {0, };

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "Enable" )==0 )
	{
		cwmp_cfg_get(CWMP_FORWARDING_ENABLE, (void*)buf, sizeof(buf));
		*data = booldup(0);	// return always false
	}else if( nv_strcmp( lastname, "DestIPAddress" )==0 )
	{
		cwmp_cfg_get(CWMP_FORWARDING_DEST_IPADDR, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "DestSubnetMask" )==0 )
	{
		cwmp_cfg_get(CWMP_FORWARDING_DEST_SUBNETMASK, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "GatewayIPAddress" )==0 )
	{
		cwmp_cfg_get(CWMP_FORWARDING_GATEWAY_IPADDR, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else{
		return ERR_9005;
	}

	return 0;
}
int set_Forwarding(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
	char *buf = data;
	int len = 0;
	
	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1; 
	if( entity->type!=type ) return ERR_9006;

	if( nv_strcmp( lastname, "Enable" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if (len==0)
			cwmp_cfg_set( CWMP_FORWARDING_ENABLE, (void *)"", 0);
		if( len < 64 )
			cwmp_cfg_set( CWMP_FORWARDING_ENABLE, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;
	}else if( nv_strcmp( lastname, "DestIPAddress" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_FORWARDING_DEST_IPADDR, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_FORWARDING_DEST_IPADDR, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else if( nv_strcmp( lastname, "DestSubnetMask" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_FORWARDING_DEST_SUBNETMASK, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_FORWARDING_DEST_SUBNETMASK, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else if( nv_strcmp( lastname, "GatewayIPAddress" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_FORWARDING_GATEWAY_IPADDR, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_FORWARDING_GATEWAY_IPADDR, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else 
		return ERR_9005;
	
	return 0;
}
#endif /* __PRMT_FORWARINDG_C__ */

