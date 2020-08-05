#ifndef __PRMT_VENDOR_CONFIG_FILE_C__
#define __PRMT_VENDOR_CONFIG_FILE_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_vendor_config_file.h"

struct sCWMP_ENTITY tVendorConfigFile[] = {
	/*(name,		type,				flag,	 	accesslist,	getvalue,				setvalue,	next_table,	sibling)*/
	{"Name",		eCWMP_tSTRING,		CWMP_READ,	NULL,		get_VendorConfigFile,	NULL,		NULL,		NULL},
	{"Version",		eCWMP_tSTRING,		CWMP_READ,	NULL,		get_VendorConfigFile,	NULL,		NULL,		NULL},
	{"Date",		eCWMP_tSTRING,		CWMP_READ,	NULL,		get_VendorConfigFile,	NULL,		NULL,		NULL},
	{"Description",	eCWMP_tSTRING,		CWMP_READ,	NULL,		get_VendorConfigFile,	NULL,		NULL,		NULL},
	{"",			eCWMP_tNONE,		0,			NULL,		NULL,					NULL,		NULL,		NULL}
};

struct sCWMP_ENTITY	tVendorConfigMap[] = {
	{"1",			eCWMP_tOBJECT, 		CWMP_READ,	NULL,		NULL,	NULL,	tVendorConfigFile,	NULL},
	{"",			eCWMP_tNONE,		0,			NULL,		NULL,	NULL,	NULL,				NULL}
};

int get_VendorConfigFile(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[256] = {0};
	int idx = 0;
	char *ptr;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
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
	
	if( nv_strcmp( lastname, "Name" )==0 )
	{
		//do nothing
		//cwmp_cfg_get(CWMP_VENDOR_CONFIGFILE_NAME, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf);
	}else if( nv_strcmp( lastname, "Version" )==0 )
	{
		char buf[64] = "";
		char *ptr1 = NULL;

		//format??
		//sample -> pvs_conf_ver=1.20.00_000

		if (idx == 1) {
			ptr1 = nvram_safe_get_r("pvs_conf_ver", buf, 64);
			snprintf((char*)ptr, STRLEN(ptr1), "%s", *ptr1?ptr1:"000");
			*data = strdup( (char*)buf );
		} else {
			return ERR_9007;
		}
	}
	else if( nv_strcmp( lastname, "Date" )==0 )
	{
		//cwmp_cfg_get(CWMP_VENDOR_CONFIGFILE_DATE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf);
	}else if( nv_strcmp( lastname, "Description" )==0 )
	{
		//cwmp_cfg_get(CWMP_VENDOR_CONFIGFILE_DESCRIPTION, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf);
	}else{
		return ERR_9005;
	}

	return 0;
}

#endif /* __PRMT_USERINTERFACE_C__ */

