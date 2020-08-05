#ifndef __PRMT_ASSOCIATEDDEVICE_C__
#define __PRMT_ASSOCIATEDDEVICE_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "bcm_param_api.h"
#include "prmt_associateddevice.h"

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tAssociatedDevice[] = {
	/*(name,						type,				flag,	 		accesslist,		etvalue,				setvalue,		next_table,	sibling)*/
	{"AssociatedDeviceMACAddress",		eCWMP_tSTRING,		CWMP_READ,		NULL,			get_AssociatedDevice,	NULL,			NULL,			NULL},
	{"AssociatedDeviceIPAddress",		eCWMP_tSTRING,		CWMP_READ,		NULL,			get_AssociatedDevice,	NULL,			NULL,			NULL},
#if 0
	{"AssocDeviceAuthState",		eCWMP_tBOOLEAN,		CWMP_READ,		NULL,			get_AssociatedDevice,	NULL,			NULL,			NULL},
	{"LastReqUnicastCipher",		eCWMP_tSTRING,		CWMP_READ,		NULL,			get_AssociatedDevice,	NULL,			NULL,			NULL},
	{"LastReqMulticastCipher",		eCWMP_tSTRING,		CWMP_READ,		NULL,			get_AssociatedDevice,	NULL,			NULL,			NULL},
	{"LastPMKId",					eCWMP_tSTRING,		CWMP_READ,		NULL,			get_AssociatedDevice,	NULL,			NULL,			NULL},
	{"LastDataTransmitRate",		eCWMP_tSTRING,		CWMP_READ,		NULL,			get_AssociatedDevice,	NULL,			NULL,			NULL},
#endif
	{"",							eCWMP_tNONE,		0,				NULL,			NULL,					NULL,			NULL,			NULL}
};
struct sCWMP_ENTITY tAssocObj[] = {
	{"0",							eCWMP_tOBJECT,		CWMP_READ|CWMP_WRITE|CWMP_LNKLIST,	NULL, 	NULL,		NULL,			tAssociatedDevice,	NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

int AssocObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	unsigned int i;
#if 0
	int idx, wl_idx, wl_subidx;
	char *ptr;

	ptr = strstr(name, "WLANConfiguration.");
	if (ptr && STRLEN(ptr) > STRLEN("WLANConfiguration."))
		ptr += STRLEN("WLANConfiguration.");
	idx = atoi(ptr)+1;

	wl_idx = idx % 2;
	wl_subidx = idx/2;
#endif

	switch(type) {
	case eCWMP_tINITOBJ:
	{
		int ret;
		struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;
		for(i=0; i < 128; i++) {
			ret = create_Object(c, tAssocObj, sizeof(tAssocObj), 1, i+1);
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

int get_AssociatedDevice(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[256] = {0};
	int idx=0, wl_idx, wl_subidx;
	char *ptr;
	int res;
	static int num=-1;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	ptr = strstr(name, "WLANConfiguration.");
	if (ptr && STRLEN(ptr) > STRLEN("WLANConfiguration.")) {
		ptr += STRLEN("WLANConfiguration.");
		idx = atoi(ptr);
	}

	if (idx <= 0)
		return ERR_9005;

#if 0
	wl_idx = (idx+1) % 2;
	wl_subidx = (idx+1)/2;
#else
	//RTL
	//WLAN0_VAP0 ~ WLAN0_VAP4 : 5GHz
	//WLAN1_VAP0 ~ WLAN1_VAP4 : 2.4GHz

	//MO WLAN idx
	//idx : 1,3,5,7 : 2.4GHz
	//idx : 2,4,6,8 : 5GHz

	get_wlan_idxes(idx, &wl_idx, &wl_subidx);
#endif

	ptr = strstr(name, "AssociatedDevice.");
	idx = 0;
	if (ptr && STRLEN(ptr)>STRLEN("AssociatedDevice.")) {
		ptr += STRLEN("AssociatedDevice.");
		idx = atoi(ptr);
	}
	if (idx <= 0)
		return ERR_9005;

	idx -= 1;
	if (idx==0 && num < 0) {
		num = get_wl_client_info(wl_idx, wl_subidx);
	}
	
	if (idx>= num) {
		if (num >= 0)
			num=-1;
		return ERR_9005;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "AssociatedDeviceMACAddress" )==0 )
	{
		get_assocDevice_mac(buf, sizeof(buf), idx);
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "AssociatedDeviceIPAddress" )==0 )
	{
		get_assocDevice_ip(buf, sizeof(buf), idx);
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "AssociatedDeviceAuthState" )==0 )
	{
		*data = booldup( atoi(buf) );
	}else if( nv_strcmp( lastname, "LastReqUnicastCipher" )==0 )
	{
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "LastReqMulticastCipher" )==0 )
	{
		*data = strdup("");
	}else if( nv_strcmp( lastname, "LastPMKId" )==0 )
	{
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "LastDataTransmitRate" )==0 )
	{
		*data = strdup( (char*)buf );
	}else{
		return ERR_9005;
	}

	return 0;
}
#endif /* __PRMT_ASSOCIATEDDEVICE_C__ */
