#ifndef __PRMT_IGD_C__
#define __PRMT_IGD_C__

#include "prmt_igd.h"
#include "prmt_deviceinfo.h"
#include "prmt_mngmtserver.h"
#include "prmt_timeinfo.h"
#include "prmt_layer3_forwarding.h"
#include "prmt_laninterface.h"
#include "prmt_manageable_device.h"
#include "prmt_vendor_config_file.h"
#include "prmt_landevice.h"
#include "prmt_wandevice.h"
#include "prmt_forwarding.h"
#include "prmt_lanhostconfmngmt.h"
#include "prmt_lanethernetinterfaceconf.h"
#include "prmt_wlanconf.h"
#include "prmt_hosts.h"
#include "prmt_wancommoninterfaceconf.h"
#include "prmt_wanethernetinterfaceconf.h"
#include "prmt_wanconnectiondevice.h"
#include "prmt_wlan.h"
#include "prmt_queuemngmt.h"
#include "prmt_ipinterface.h"
#include "prmt_stats.h"
#include "prmt_wps.h"
#include "prmt_host.h"
#include "prmt_connection.h"
#include "prmt_associateddevice.h"
#include "prmt_wanethernetlinkconfig.h"
#include "prmt_wanipconnection.h"
#include "prmt_bridge.h"
#include "prmt_ethernetstats.h"
#include "prmt_portmapping.h"
#include "bcm_param_api.h"
#include <bcmnvram.h>

struct sCWMP_ENTITY tIGD_first[] =
{
	{"Bridge",		eCWMP_tOBJECT,		CWMP_READ|CWMP_WRITE,	NULL,		NULL,		BridgeObj,		NULL,		NULL},
	{"",			eCWMP_tNONE,		0,						NULL,		NULL,		NULL,		NULL,			NULL}
};

struct sCWMP_ENTITY tIGD[] =
{
	/*(name,				type,			flag,		accesslist,	getvalue,	setvalue,	next_table,			sibling)*/
	{"LANDeviceNumberOfEntries", eCWMP_tUINT,	CWMP_READ,	NULL,	get_DevSummary, NULL,	NULL,				NULL},	
	{"WANDeviceNumberOfEntries", eCWMP_tUINT,	CWMP_READ,	NULL,	get_DevSummary, NULL,	NULL,				NULL},
	{"DeviceSummary",		eCWMP_tSTRING, 	CWMP_READ,	NULL,		get_DevSummary, NULL,	NULL,				NULL},		
	{"DeviceInfo",			eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tDeviceInfo,		NULL},
//	{"DeviceConfig",		eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tDeviceConfig,		NULL},
	{"ManagementServer",	eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tManagementServer,	NULL},
	{"Time",				eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tTimeInfo,			 	NULL},
///	{"Layer3Forwarding",	eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tLayer3Forwarding,		NULL},
	{"LANDevice",			eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tLANDevice,				NULL},
	{"WANDevice",			eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tWANDevice,				NULL},
/*
	{"Services",			eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tIGD_first?,		NULL},
*/
///	{"Layer2Bridging",		eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tIGD_first,		NULL},
///	{"QueueManagement",		eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tQueueMngmt,		NULL},
//	{"Capabilities",		eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tCapability,		NULL},
//	{"DownloadDiagnostics",
//	{"UploadDiagnostics",
//	{"UDPEchoConfig",
//	{"CaptivePortal",
 
///	{"LANInterfaces", 		eCWMP_tOBJECT, 	CWMP_READ,	NULL, 		NULL, 		NULL,		tLanInterface, 			NULL},
	{"",					eCWMP_tNONE,	0,			NULL,		NULL,		NULL,		NULL,				NULL}
};
struct sCWMP_ENTITY tROOT[] =
{
	/*(name,					type,			flag,		accesslist,	getvalue,	setvalue,	next_table,	sibling)*/
	{"InternetGatewayDevice",	eCWMP_tOBJECT,	CWMP_READ,	NULL,		NULL,		NULL,		tIGD,			NULL},
	{"",						eCWMP_tNONE,	0,			NULL,		NULL,		NULL,		NULL,			NULL}
};

int get_DevSummary(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if (!nv_strcmp(lastname, "LANDeviceNumberOfEntries")) {
		*data = uintdup(1);

	} else if (!nv_strcmp(lastname, "WANDeviceNumberOfEntries")) {
		*data = uintdup(1);

	} else if (!nv_strcmp(lastname, "DeviceSummary")) {
		char tmp[64] = {0, };
		char model_name[32] = {0, };
		get_model(model_name, sizeof(model_name), UPPER);
		snprintf(tmp, sizeof(tmp), "SEIKO %s", model_name);
		*data = strdup(tmp);

	} else
		return ERR_9005;

	return 0;
}
#endif /* __PRMT_IGD_C__ */
