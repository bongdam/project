#ifndef __PRMT_LANDEVICE_C__
#define __PRMT_LANDEVICE_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "bcm_cfg_api.h"
#include "prmt_landevice.h"
#include "prmt_lanhostconfmngmt.h"
#include "prmt_lanethernetinterfaceconf.h"
#include "prmt_wlanconf.h" 
#include "prmt_hosts.h"

struct sCWMP_ENTITY tLANHOSTCONFTBL[] = {
	/*(name,							type,				flag,	 			accesslist,	getvalue,	setvalue,	next_table,			sibling)*/
	{"LANEthernetInterfaceNumberOfEntries",	eCWMP_tUINT,	CWMP_READ,				NULL,	get_LANDevice,		NULL,		NULL,			NULL},
	{"LANUSBInterfaceNumberOfEntries",		eCWMP_tUINT,	CWMP_READ,				NULL,	get_LANDevice,		NULL,		NULL,			NULL},
	{"LANWLANConfigurationNumberOfEntries",	eCWMP_tUINT,	CWMP_READ,				NULL,	get_LANDevice,		NULL,		NULL,			NULL},
	{"LANHostConfigManagement", 			eCWMP_tOBJECT, 	CWMP_READ, 			 	NULL,   NULL,      			NULL,       tLanHostConfMngmt,  NULL},
	{"LANEthernetInterfaceConfig",			eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE,	NULL,	NULL,				LANETHINFObj,	NULL, NULL},
	{"WLANConfiguration",					eCWMP_tOBJECT,  CWMP_READ|CWMP_WRITE,	NULL,	NULL,				WLANConfObj,	NULL,		NULL},
///TODO	{"Hosts",								eCWMP_tOBJECT,	CWMP_READ,				NULL,	NULL,				NULL, tHosts,	NULL},
	{"",									eCWMP_tNONE,		0,			NULL,		NULL,				NULL,		NULL,			NULL}
};

struct sCWMP_ENTITY tLANDevice[] = {
	/*(name,		type,			flag,	 	accesslist,	getvalue,	setvalue,	next_table,		sibling)*/
	{"1",			eCWMP_tOBJECT, 		0,		NULL,		NULL, 		NULL,		tLANHOSTCONFTBL,	NULL},
	{"",			eCWMP_tNONE,		0,		NULL,		NULL,		NULL,		NULL,			NULL}
};

int get_LANDevice(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	//unsigned char buf[256] = {0};

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if (!nv_strcmp(lastname, "LANEthernetInterfaceNumberOfEntries")) {
		//cwmp_cfg_get(CWMP_LAN_ETHERNET_INTERFACE_NUM_ENTRIES, (void*)buf, sizeof(buf));
		*data = uintdup(1);

	} else if (!nv_strcmp(lastname, "LANUSBInterfaceNumberOfEntries")) {
		//cwmp_cfg_get(CWMP_LAN_USB_INTERFACE_NUM_ENTRIES, (void*)buf, sizeof(buf));
		*data = uintdup(0);

	} else if (!nv_strcmp(lastname, "LANWLANConfigurationNumberOfEntries")) {
		//cwmp_cfg_get(CWMP_LAN_WLAN_CONF_NUM_ENTRIES, (void*)buf, sizeof(buf));
		*data = uintdup(2);

	} else
		return ERR_9005;

	return 0;
}

#endif /* __PRMT_LANDEVICE_C__ */

