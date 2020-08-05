#ifndef __PRMT_HOST_C__
#define __PRMT_HOST_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_host.h"
#include "bcm_param_api.h"

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tHost[] = {
	/*(name,								type,							flag,	 					accesslist,	getvalue,			setvalue,		next_table,	sibling)*/
	{"IPAddress",		eCWMP_tSTRING,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"AddressSource",	eCWMP_tSTRING,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"LeaseTimeRemaining",	eCWMP_tINT,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"MACAddress",		eCWMP_tSTRING,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"HostName",		eCWMP_tSTRING,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"InterfaceType",	eCWMP_tSTRING,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"Active",			eCWMP_tBOOLEAN,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"Layer2Interface",	eCWMP_tSTRING,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"VendorClassID",	eCWMP_tSTRING,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"ClientID",		eCWMP_tSTRING,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"UserClassID",		eCWMP_tSTRING,		CWMP_READ,		NULL,			get_Host,		NULL,	NULL,	NULL},
	{"",				eCWMP_tNONE,		0,				NULL,			NULL,			NULL,	NULL,	NULL}
};
struct sCWMP_ENTITY tHostMAP[] = {
	{"0",	eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE|CWMP_LNKLIST,	NULL,		NULL,			NULL,	tHost,	NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

struct ip_tbl_t List[64];
static int inited = 0;
static int num = -1;

int init_wired_devicelist(void)
{
	memset(List, 0, sizeof(List));
	inited = 1;
	num = -1;
	return 0;
}

int HostObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	int i;
	struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;

	switch (type) {
	case eCWMP_tINITOBJ:
		init_wired_devicelist();
		if (IS_BRIDGE_MODE) 
			return 0;
		for (i = 0; i < 64; i++) {
			if (create_Object(c, tHostMAP, sizeof(tHostMAP),1, i + 1) < 0)
				break;
		}
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

int get_Host(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[256] = {0, };
	char *deli = "Host.";
	char *ptr = NULL;
	int idx = 0;
	int list_idx = -1;
	int i = 0;
	int port_num = 0;
	int name_len = 0;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if (IS_BRIDGE_MODE)
		return 0;

	ptr = strstr(name, deli);
	if (ptr && STRLEN(ptr)>STRLEN(deli)) {
		ptr += STRLEN(deli);
		idx = atoi(ptr);
	}

	if (idx <= 0 && idx > 64)
		return ERR_9005;

	if (inited == 1) {
		inited = 0;
		num = get_device_info(&List[0]);
		if (num < 1)
			return ERR_9005;

	} else {
		if (idx > num)
			return ERR_9005;
	}

	name_len = STRLEN(name);

	i = idx - 1;

	port_num = get_connected_port_with_mac(List[i].strmac);
	if (port_num >= 1 && port_num <= 4) {	//got it!!!
		list_idx = i;
	}

	if (list_idx == -1)
		return ERR_9005;

	snprintf(name, name_len + 1, "InternetGatewayDevice.LANDevice.1.Hosts.Host.%d.%s", port_num, lastname);

	if( nv_strcmp( lastname, "IPAddress" )==0 )
	{
		*data = strdup(List[list_idx].strip);
	}else if( nv_strcmp( lastname, "AddressSource" )==0 )
	{
		cwmp_cfg_get(CWMP_HOST_ADDR_SOURCE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "LeaseTimeRemaining" )==0 )
	{
		*data = intdup(List[list_idx].expires);
	}else if( nv_strcmp( lastname, "MACAddress" )==0 )
	{
		//MO Spec - xx:xx:xx:xx:xx:xx(v0.5) -> xxxx.xxxx.xxxx(v0.8)
		char tmp_mac[32] = {0, };
		snprintf(tmp_mac, sizeof(tmp_mac), "%s", List[list_idx].strmac);
		*data = strdup(conv_mac_format(tmp_mac));
	}else if( nv_strcmp( lastname, "HostName" )==0 )
	{
		cwmp_cfg_get(CWMP_HOST_NAME, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "InterfaceType" )==0 )
	{
		cwmp_cfg_get(CWMP_HOST_INTERFACETYPE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "Active" )==0 )
	{
		cwmp_cfg_get(CWMP_HOST_ACTIVE, (void*)buf, sizeof(buf));
		*data = booldup( atoi(buf) );
	}else if( nv_strcmp( lastname, "Layer2Interface" )==0 )
	{
		cwmp_cfg_get(CWMP_HOST_LAYER2INTERFACE, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "VendorClassID" )==0 )
	{
		cwmp_cfg_get(CWMP_HOST_VENDORCLASSID, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "ClientID" )==0 )
	{
		cwmp_cfg_get(CWMP_HOST_CLIENTID, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "UserClassID" )==0 )
	{
		cwmp_cfg_get(CWMP_HOST_USERCLASSID, (void*)buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else{
		return ERR_9005;
	}

	return 0;
}
#endif /* __PRMT_HOST_C__ */
