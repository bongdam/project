#ifndef __PRMT_WANCOMMONINTERFACECONF_C__
#define __PRMT_WANCOMMONINTERFACECOF_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "bcm_param_api.h"
#include "prmt_wancommoninterfaceconf.h"

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tWANCommonInterfaceConf[] = {
	/*(name,												type,							flag,	 										accesslist,	getvalue,										setvalue,												next_table,	sibling)*/
	{"EnabledForInternet",			eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_WANCommonInterfaceConf,		set_WANCommonInterfaceConf,		NULL,			NULL},
	{"WANAccessType",				eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"Layer1UpstreamMaxBitRate",	eCWMP_tUINT,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"Layer1DownstreamMaxBitRate",	eCWMP_tUINT,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"PhysicalLinkStatus",			eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"WANAccessProvider",			eCWMP_tSTRING,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"TotalBytesSent",				eCWMP_tUINT,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"TotalBytesReceived",			eCWMP_tUINT,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"TotalPacketsSent",			eCWMP_tUINT,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"TotalPacketsReceived",		eCWMP_tUINT,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"MaximumActiveConnections",	eCWMP_tUINT,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"NumberOfActiveConnections",	eCWMP_tUINT,	CWMP_READ,				NULL,		get_WANCommonInterfaceConf,		NULL,							NULL,			NULL},
	{"",							eCWMP_tNONE,	0,						NULL,		NULL,							NULL,							NULL,			NULL}
};

int get_WANCommonInterfaceConf(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	unsigned char buf[256] = {0};

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "EnabledForInternet" )==0 )
	{
		cwmp_cfg_get(CWMP_ENABLED_INTERNET, (void*)buf, sizeof(buf));
		*data = booldup(1);
	}else if( nv_strcmp( lastname, "WANAccessType" )==0 )
	{
		cwmp_cfg_get(CWMP_WAN_ACCESSTYPE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "Layer1UpstreamMaxBitRate" )==0 )
	{
		cwmp_cfg_get(CWMP_LAYER1_UPSTREAM_MAXBITRATE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "Layer1DownstreamMaxBitRate" )==0 )
	{
		cwmp_cfg_get(CWMP_LAYER1_DOWNSTREAM_MAXBITRATE, (void*)buf, sizeof(buf));
		*data = booldup(1 );
	}else if( nv_strcmp( lastname, "PhysicalLinkStatus" )==0 )
	{
		cwmp_cfg_get(CWMP_PHYSICAL_LINK_STATUS, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "WANAccessProvider" )==0 )
	{
		cwmp_cfg_get(CWMP_WAN_ACCESS_PROVIDER, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "TotalBytesSent" )==0 )
	{
		*data = uintdup(0);	// youngho : beyond LG U+ spec
	}else if( nv_strcmp( lastname, "TotalBytesReceived" )==0 )
	{
		*data = uintdup(0);	// youngho : beyond LG U+ spec
	}else if( nv_strcmp( lastname, "TotalPacketsSent" )==0 )
	{
		*data = uintdup(0);	// youngho : beyond LG U+ spec
	}else if( nv_strcmp( lastname, "TotalPacketsReceived" )==0 )
	{
		*data = uintdup(0);	// youngho : beyond LG U+ spec
	}else if( nv_strcmp( lastname, "MaximumActiveConnections" )==0 )
	{
		*data = uintdup(1);
	}else if( nv_strcmp( lastname, "NumberOfActiveConnections" )==0 )
	{
		*data = uintdup(1);
	}else{
		return ERR_9005;
	}

	return 0;
}
int set_WANCommonInterfaceConf(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{    
	char    *lastname = entity->name;
	char    *buf=data;
	int     len=0;
	
	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1; 
	if( entity->type!=type ) return ERR_9006;

	if( nv_strcmp( lastname, "EnabledForInternet" )==0 )
	{
		if( buf ) len = STRLEN( buf );
		if (len==0)
			cwmp_cfg_set( CWMP_ENABLED_INTERNET, (void *)"", 0);
		if( len < 64 )
			cwmp_cfg_set( CWMP_ENABLED_INTERNET, (void *)buf, len);
		else 
			return ERR_9007;
		return 0;
	}else 
		return ERR_9005;
	
	return 0;
}
#endif /* __PRMT_WANCOMMONINTERFACECONF_C__ */
