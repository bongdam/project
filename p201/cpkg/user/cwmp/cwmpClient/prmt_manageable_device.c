#ifndef __PRMT_MANAGEABLE_DEVICE_C__
#define __PRMT_MANAGEABLE_DEVICE_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include <shutils.h>
#include "prmt_manageable_device.h"
#include "bcm_param_api.h"

struct sCWMP_ENTITY tManageableDevice[] = {
	/*(name,					type,				flag,	 	accesslist,	getvalue,				setvalue,	next_table,	sibling)*/
	{"ManufacturerOUI",			eCWMP_tSTRING,		CWMP_READ,	NULL,		get_ManageableDevice,	NULL,		NULL,		NULL},
	{"SerialNumber",			eCWMP_tSTRING,		CWMP_READ,	NULL,		get_ManageableDevice,	NULL,		NULL,		NULL},
	{"ProductClass",			eCWMP_tSTRING,		CWMP_READ,	NULL,		get_ManageableDevice,	NULL,		NULL,		NULL},
	{"Host",					eCWMP_tSTRING,		CWMP_READ,	NULL,		get_ManageableDevice,	NULL,		NULL,		NULL},
	{"",						eCWMP_tNONE,		0,			NULL,		NULL,					NULL,		NULL,		NULL}
};

int get_ManageableDevice(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[256] = {0};
	int idx = 0;
	char *ptr;
	
	if( (name==NULL) || (type==NULL) || (data==NULL) ||	(entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;
	
	snprintf(buf, sizeof(buf), "%s", name);
	ptr = strrchr(buf, '.');
	
	if (ptr)
		*ptr = 0;
	
	ptr = strrchr(buf, '.');
	
	if (ptr && STRLEN(ptr) > 1)
		idx = atoi(ptr+1);
	
	if (idx <= 0 || idx > 1)
		return ERR_9005;
	
	if( nv_strcmp( lastname, "ManufacturerOUI" )==0 )
	{
		unsigned char a[6] = "";
		char buf[32] = "";

		//get_macaddr(buf, sizeof(buf), 0, 0);
		get_wan_macaddr(buf, sizeof(buf), UPPER);
		ether_atoe(buf, a);
		snprintf(buf, sizeof(buf), "%02X%02X%02X", a[0], a[1], a[2]);
		*data =	strdup((char*)buf);    
	}else if( nv_strcmp( lastname, "SerialNumber" )==0 )
	{
		//nvram_safe_get_r("serial_num", buf, sizeof(buf));
		nvram_safe_get_r("HW_SERIAL_NO", buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "ProductClass" )==0 )
	{
		*data = strdup("CHGW");
	}else if( nv_strcmp( lastname, "Host" )==0 )
	{
		//cwmp_cfg_get(CWMP_HOST, (void*)buf, sizeof(buf));
		*data = strdup("");
	}else
		return ERR_9005;

	return 0;
}

#endif /* __PRMT_MANAGEABLE_DEVICE_C__ */

