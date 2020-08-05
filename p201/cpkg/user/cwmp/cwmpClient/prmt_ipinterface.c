#ifndef __PRMT_IPINTERFACE_C__
#define __PRMT_IPINTERFACE_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_ipinterface.h"

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tIPInterface[] = {
	/*(name,			type,			flag,			accesslist,	getvalue,		setvalue,			next_table,	sibling)*/
	{"Enable",			eCWMP_tBOOLEAN,		CWMP_WRITE|CWMP_READ,	NULL,		get_IPInterface,	set_IPInterface,		NULL,		NULL},
	{"IPInterfaceIPAddress",	eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_IPInterface,	set_IPInterface,		NULL,		NULL},
	{"IPInterfaceSubnetMask",	eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_IPInterface,	set_IPInterface,		NULL,		NULL},
	{"IPInterfaceAddressingType",	eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_IPInterface,	set_IPInterface,		NULL,		NULL},
	{"",				eCWMP_tNONE,		0,			NULL,		NULL,			NULL,				NULL,		NULL}
};

int get_IPInterface(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	//char buf[256] = {0};

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "Enable" )==0 )
	{
#if 0
		cwmp_cfg_get(CWMP_IP_INTERFACE_ENABLE, (void*)buf, sizeof(buf));
		*data = booldup( atoi(buf) );
#endif
	}else if( nv_strcmp( lastname, "IPInterfaceIPAddress")==0 )
	{
#if 0
		cwmp_cfg_get(CWMP_IP_INTERFACE_IPADDR, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
#endif
	}else if( nv_strcmp( lastname, "IPInterfaceSubnetMask")==0 )
	{
#if 0
		cwmp_cfg_get(CWMP_IP_INTERFACE_SUBNETMASK, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
#endif
	}else if( nv_strcmp( lastname, "IPInterfaceAddressingType")==0 )
	{
#if 0
		cwmp_cfg_get(CWMP_IP_INTERFACE_ADDRTYPE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
#endif
	}else{
		return ERR_9005;
	}

	return 0;
}
int set_IPInterface(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char	*lastname = entity->name;
	//char 	*buf=data;
	//int 	len=0;
	
	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;
	
	if( nv_strcmp( lastname, "Enable" )==0 )
	{
#if 0
		if( buf ) len = STRLEN( buf );
		if( len ==0 )
			cwmp_cfg_set( CWMP_IP_INTERFACE_ENABLE, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_IP_INTERFACE_ENABLE, (void *)buf, len);
		else
			return ERR_9007;
		return 0;
#endif
	}else if( nv_strcmp( lastname, "IPInterfaceIPAddress")==0 )
	{
#if 0
		if( buf ) len = STRLEN( buf );
		if( len ==0 )
			cwmp_cfg_set( CWMP_IP_INTERFACE_IPADDR, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_IP_INTERFACE_IPADDR, (void *)buf, len);
		else
			return ERR_9007;
		return 0;
#endif
	}else if( nv_strcmp( lastname, "IPInterfaceSubnetMask")==0 )
	{
#if 0
		if( buf ) len = STRLEN( buf );
		if( len ==0 )
			cwmp_cfg_set( CWMP_IP_INTERFACE_SUBNETMASK, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_IP_INTERFACE_SUBNETMASK, (void *)buf, len);
		else
			return ERR_9007;
		return 0;
#endif
	}else if( nv_strcmp( lastname, "IPInterfaceAddressingType")==0 )
	{
#if 0
		if( buf ) len = STRLEN( buf );
		if( len ==0 )
			cwmp_cfg_set( CWMP_IP_INTERFACE_ADDRTYPE, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_IP_INTERFACE_ADDRTYPE, (void *)buf, len);
		else
			return ERR_9007;
		return 0;
#endif
	}else
		return ERR_9005; 
	return 0;
}
#endif /* __PRMT_IPINTERFACE_C__ */
