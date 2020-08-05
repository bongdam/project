#ifndef __PRMT_WPS_C__
#define __PRMT_WPS_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_wps.h"

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tWPS[] = {
	/*(name,							type,							flag,	 										accesslist,	getvalue,		setvalue,		next_table,	sibling)*/
	{"Enable",				eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,			get_WPS,		set_WPS,		NULL,			NULL},
	{"DeviceName",			eCWMP_tSTRING,		CWMP_READ,							NULL,			get_WPS,		NULL,			NULL,			NULL},
	{"DevicePassword",		eCWMP_tSTRING,			CWMP_WRITE|CWMP_READ,	NULL,			get_WPS,		set_WPS,		NULL,			NULL},
	{"",									eCWMP_tNONE,			0,												NULL,			NULL,			NULL,			NULL,			NULL}
};

int get_WPS(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[256] = {0};

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "Enable" )==0 )
	{
		cwmp_cfg_get(CWMP_WPS_ENABLE, (void*)buf, sizeof(buf));
		*data = booldup( atoi(buf) );
	}else if( nv_strcmp( lastname, "DeviceName")==0 )
	{
		cwmp_cfg_get(CWMP_WPS_DEVICENAME, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "DevicePassword")==0 )
	{
		*data = strdup("");
	}else{
		return ERR_9005;
	}

	return 0;
}
int set_WPS(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char	*lastname = entity->name;
	char 	*buf=data;
	int 	len=0;
	
	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;
	
	if( nv_strcmp( lastname, "Enable" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len ==0 )
			cwmp_cfg_set( CWMP_WPS_ENABLE, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_WPS_ENABLE, (void *)buf, len);
		else
			return ERR_9007;
		return 0;
	}else if( nv_strcmp( lastname, "DeviceName")==0 )
	{
		return 0;
	}else if( nv_strcmp( lastname, "DevicePassword")==0 )
	{
		if( buf ) len = STRLEN( buf );
		if( len ==0 )
			cwmp_cfg_set( CWMP_WPS_DEVICEPW, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_WPS_DEVICEPW, (void *)buf, len);
		else
			return ERR_9007;
		return 0;
	}else
		return ERR_9005; 
	return 0;
}
#endif /* __PRMT_WPS_C__ */
