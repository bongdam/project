#ifndef __PRMT_PORTMAPPING_C__
#define __PRMT_PORTMAPPING_C__

#include <stdio.h>
#include <string.h>
#include "prmt_portmapping.h"
#include "bcm_param_api.h"
#include <bcmnvram.h>

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tPortMapping[] = {
	/*(name,						type,			flag,	 				 	accesslist,		getvalue,			setvalue,			next_table,	sibling)*/
	{"PortMappingEnabled",			eCWMP_tBOOLEAN,		CWMP_WRITE|CWMP_READ,	NULL,			get_PortMapping,	set_PortMapping,	NULL,			NULL},
	{"PortMappingLeaseDuration",	eCWMP_tUINT,		CWMP_WRITE|CWMP_READ,	NULL,			get_PortMapping,	set_PortMapping,	NULL,			NULL},
	{"RemoteHost",					eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,			get_PortMapping,	set_PortMapping,	NULL,			NULL},
	{"ExternalPort",				eCWMP_tUINT,		CWMP_WRITE|CWMP_READ,	NULL,			get_PortMapping,	set_PortMapping,	NULL,			NULL},
	{"InternalPort",				eCWMP_tUINT,		CWMP_WRITE|CWMP_READ,	NULL,			get_PortMapping,	set_PortMapping,	NULL,			NULL},
	{"PortMappingProtocol",			eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,			get_PortMapping,	set_PortMapping,	NULL,			NULL},
	{"InternalClient",				eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,			get_PortMapping,	set_PortMapping,	NULL,			NULL},
	{"PortMappingDescription",		eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,			get_PortMapping,	set_PortMapping,	NULL,			NULL},
	{"ExternalPortEndRange",		eCWMP_tUINT,		CWMP_WRITE|CWMP_READ,	NULL,			get_PortMapping,	set_PortMapping,	NULL,			NULL},
	{"",							eCWMP_tNONE,		0,						NULL,			NULL,				NULL,				NULL,			NULL}
};
struct sCWMP_ENTITY pmMAP[] = {
	{"0",	eCWMP_tOBJECT,	CWMP_WRITE|CWMP_READ|CWMP_LNKLIST,			NULL,	NULL,	NULL,	tPortMapping, NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

static int port_map_cnt;
struct _port_map_t portMapList[32];

int PortMapObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	//#warning PortMapObj Object need to check.
	struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;
	int i;

	switch(type) {
	case eCWMP_tINITOBJ:
		if (IS_BRIDGE_MODE)
			return 0;

		port_map_cnt = get_fwd_num();
		get_fwd_list(portMapList);
		for (i=0; i<port_map_cnt;i++)
			if (create_Object(c, pmMAP, sizeof(pmMAP), 1, i+1)<0)
				break;
		add_objectNum(name, i);
		return 0;
	case eCWMP_tADDOBJ:
	case eCWMP_tDELOBJ:
	case eCWMP_tUPDATEOBJ:
		return 0;
	default:
		break;
	}

	return -1;
}

int get_PortMapping(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	//#warning PortMappin.{i} Object need to check.
	char *lastname = entity->name;
	unsigned char buf[256] = {0};
	char *ptr, *deli="PortMapping.";
	struct _port_map_t *info;
	int idx = -1;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	if (IS_BRIDGE_MODE)
		return 0;

	*type = entity->type;
	*data = NULL;
	ptr = strstr(name, deli);
	if (ptr && STRLEN(ptr)>STRLEN(deli)) {
		ptr += STRLEN(deli);
		idx = atoi(ptr);
	}

	if (idx<=0 || idx > port_map_cnt)
		return ERR_9005;

	idx-=1;
	info = &portMapList[idx];

	if( nv_strcmp( lastname, "PortMappingEnabled" )==0 )
	{
		*data = booldup(info->enable);
	}else if( nv_strcmp( lastname, "PortMappingLeaseDuration" )==0 )
	{
		*data = uintdup(0);
	}else if( nv_strcmp( lastname, "RemoteHost" )==0 )
	{
		//Do nothing.
		cwmp_cfg_get(CWMP_PORT_MAPPING_REMOTE_HOST, (void*)buf, sizeof(buf)); 
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "ExternalPort" )==0 )
	{
		*data = uintdup(info->extPort);
	}else if( nv_strcmp( lastname, "InternalPort" )==0 )
	{
		*data = uintdup(info->intPort);
	}else if( nv_strcmp( lastname, "PortMappingProtocol" )==0 )
	{
		*data = strdup(info->protocol);
	}else if( nv_strcmp( lastname, "InternalClient" )==0 )
	{
		*data = strdup(info->srcip);
	}else if( nv_strcmp( lastname, "PortMappingDescription" )==0 )
	{
		//Do nothing.
		cwmp_cfg_get(CWMP_PORT_MAPPING_DESCRIPTION, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "ExternalPortEndRange" )==0 )
	{
		*data = uintdup(info->Range);
	}else
		return ERR_9005;

	return 0;
}

int set_PortMapping(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{    
	char    *lastname = entity->name;
	char    *buf=data;
	int     len=0;
	char *ptr, *deli="PortMapping.";
	int idx = -1;
	
	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1; 

	if (IS_BRIDGE_MODE)
		return 0;
	
	if( entity->type!=type ) return ERR_9006;

	ptr = strstr(name, deli);
	if (ptr && STRLEN(ptr)>STRLEN(deli)) {
		ptr += STRLEN(deli);
		idx = atoi(ptr);
	}

	if (idx<=0 || idx > port_map_cnt)
		return ERR_9005;
	idx-=1;

	if( nv_strcmp( lastname, "PortMappingEnabled" )==0 )
	{
		char tmpBuf[64];
		char name[24];
		char val[8];
		int en = *(int*)buf;
		char *p;

		portMapList[idx].enable = en ? 1:0;
		snprintf(name, sizeof(name), "PORTFW_TBL%d", idx + 1);
		nvram_safe_get_r(name, tmpBuf, sizeof(tmpBuf));
		p = strchr(tmpBuf, '|');
		if (p) {
			*p = 0;
			snprintf(val, sizeof(val), "|%d", en?1:0);
			strncat(tmpBuf, val, STRLEN(val));
			nvram_set(name, tmpBuf);
			return 1;
		}
		return 0;
	}else if( nv_strcmp( lastname, "PortMappingLeaseDuration" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_LEASE_DURATION, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_LEASE_DURATION, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else if( nv_strcmp( lastname, "RemoteHost" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_REMOTE_HOST, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_REMOTE_HOST, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else if( nv_strcmp( lastname, "ExternalPort" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_EXTERNAL_PORT, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_EXTERNAL_PORT, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else if( nv_strcmp( lastname, "InternalPort" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_INTERNAL_PORT, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_INTERNAL_PORT, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else if( nv_strcmp( lastname, "PortMappingProtocol" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_PROTOCOL, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_PROTOCOL, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else if( nv_strcmp( lastname, "InternalClient" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_INTERNAL_CLIENT, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_INTERNAL_CLIENT, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else if( nv_strcmp( lastname, "PortMappingDescription" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_DESCRIPTION, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_DESCRIPTION, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else if( nv_strcmp( lastname, "ExternalPortEndRange" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len==0 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_EXTERNAL_PORT_END_RANGE, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_PORT_MAPPING_EXTERNAL_PORT_END_RANGE, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;		
	}else 
		return ERR_9005;
	
	return 0;
}
#endif /* __PRMT_PORTMAPPING_C__ */

