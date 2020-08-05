#ifndef __PRMT_DEVICEINFO_C__
#define __PRMT_DEVICEINFO_C__
#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>

#include <bcmnvram.h>
#include <libytool.h>
#include <shutils.h>
#include <publicfunc.h>
#include "prmt_deviceinfo.h"
#include "prmt_vendor_config_file.h"
#include "bcm_param_api.h"

typedef enum {en_false = 0, en_true = 1} boolean;

extern void cwmpSetReboot(void);
extern void cwmpMgmtSetImmediatePolling(int res);
extern int cwmpMgmtSetIdleReset(int res);

struct sCWMP_ENTITY tDeviceInfo[] =
{
	/*(name,							type,				flag,					accesslist,	getvalue,		setvalue,		next_table,			sibling)*/
	{"Manufacturer",					eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
	{"ManufacturerOUI",					eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
	{"ModelName",						eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
///	{"Description",						eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
	{"ProductClass",					eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
	{"SerialNumber",					eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
	{"HardwareVersion",					eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
	{"SoftwareVersion",					eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
///	{"ModemFirmwareVersion",			eCWMP_tSTRING, 		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
///	{"EnabledOptions",					eCWMP_tSTRING, 		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
///	{"AdditionalHardwareVersion",		eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
///	{"AdditionalSoftwareVersion",		eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
	{"SpecVersion",						eCWMP_tSTRING,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
	{"ProvisioningCode",				eCWMP_tSTRING,		CWMP_READ|CWMP_WRITE,	NULL,		getDeviceInfo,	setDeviceInfo,	NULL,				NULL},
	{"UpTime",							eCWMP_tUINT,		CWMP_READ|CWMP_DENY_ACT,NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
///	{"FirstUseDate",					eCWMP_tDATETIME,	CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
	{"DeviceLog",						eCWMP_tSTRING,		CWMP_READ|CWMP_DENY_ACT,NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
///	{"VendorConfigFileNumberOfEntries", eCWMP_tUINT,		CWMP_READ,				NULL,		getDeviceInfo,	NULL,			NULL,				NULL},
///	{"VendorConfigFile",				eCWMP_tOBJECT,		CWMP_READ,				NULL,		NULL,			NULL,			tVendorConfigMap,	NULL},
///	{"ProcessStatus",					eCWMP_tOBJECT,		CWMP_READ,				NULL,		NULL,			NULL,			tCPUStat,			NULL},
///	{"MemoryStatus",					eCWMP_tOBJECT,		CWMP_READ,				NULL,		NULL,			NULL,			tMemStat,			NULL},
	{"",								eCWMP_tNONE,		0,						NULL,		NULL,			NULL,			NULL,				NULL}
};

int getDeviceInfo(char *name, struct sCWMP_ENTITY *entity, int *type, void **data)
{
	char *lastname = entity->name;
	char buf[128] = {0, };

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL))  {
		return -1;
	}

	CWMPDBG( 3, ( stdout, "<%s:%d> %s\n", __FUNCTION__, __LINE__, lastname));

	*type = entity->type;

	if (*data != NULL)
		free(*data);

	*data = NULL;

	if (!nv_strcmp(lastname, "Manufacturer")) {
		*data = strdup("SEIKO");

	} else if (!nv_strcmp(lastname, "ManufacturerOUI")) {
		unsigned char a[6] = "";
		get_wan_macaddr(buf, sizeof(buf), LOWER);
		ether_atoe(buf, a);
		snprintf(buf, sizeof(buf), "%02X%02X%02X", a[0], a[1], a[2]);
		*data = strdup((char*)buf);

	} else if (!nv_strcmp(lastname, "ModelName")) {
		get_model(buf, sizeof(buf), LOWER);
		*data = strdup(buf);

	} else if (!nv_strcmp(lastname, "Description")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "ProductClass")) {
		*data = strdup("CHGW");

	} else if (!nv_strcmp(lastname, "SerialNumber")) {
		//nvram_safe_get_r("serial_num", buf, sizeof(buf));
		nvram_safe_get_r("HW_SERIAL_NO", buf, sizeof(buf));
		if (buf[0])
			*data = strdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "HardwareVersion")) {
		*data = strdup("1.00");

	} else if (!nv_strcmp(lastname, "SoftwareVersion")) {
		get_version(buf, sizeof(buf), 0, 0);
		if (buf[0])
			*data = strdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "ModemFirmwareVersion")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "EnabledOptions")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "AdditionalHardwareVersion")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "AdditionalSoftwareVersion")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "SpecVersion")) {
//		cwmp_cfg_get(CWMP_SPEC_VER, (void*)buf, sizeof(buf));
		*data = strdup("1.00");

	} else if (!nv_strcmp(lastname, "ProvisioningCode")) {
		char buf[64] = {0, };
		char *ptr1;

		//format??
		//sample -> pvs_conf_ver=1.20.00_000
		ptr1 = nvram_safe_get_r("pvs_conf_ver", buf, sizeof(buf));
		snprintf(buf, sizeof(buf), "%s", *ptr1?ptr1:"000");
		*data = strdup( (char*)buf );

	} else if (!nv_strcmp(lastname, "UpTime")) {
		unsigned int res = get_uptime_mo();
		*data = uintdup(res);

	} else if (!nv_strcmp(lastname, "FirstUseDate")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "DeviceLog")) {
		char *log_filename = "/tmp/.tr069_dlog.txt";
		char dlog[LOG_MAXSIZE] = {0, };

		memset(dlog, 0, LOG_MAXSIZE);

		if (access(log_filename, F_OK) == 0)
			unlink(log_filename);

		get_diag_log_tr069(log_filename, 1);		//apply url encoding
		get_device_log_from_file(log_filename, dlog);

		if (STRLEN(dlog) > 0) {
			*data = strdup(dlog);
		} else {
			*data= strdup(buf);
		}

	} else if (!nv_strcmp(lastname, "VendorConfigFileNumberOfEntries")) {
		empty_data(*type, data);
	} else
		return ERR_9005;

	return 0;
}

int setDeviceInfo(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
#if 0
	char *buf = data;
	int len = 0;
#endif
	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;

	if (!nv_strcmp(lastname, "ProvisioningCode")) {
#if 0
		if( buf ) len = STRLEN( buf );
		if( len ==0 )
			cwmp_cfg_set( CWMP_PROVISIONINGCODE, (void *)"", 0);
		else if( len < 64 )
			cwmp_cfg_set( CWMP_PROVISIONINGCODE, (void *)buf, len);
		else
			return ERR_9007;
		return 0;
#endif
	} else
		return ERR_9005;

	return 0;
}

#endif /* __PRMT_DEVICEINFO_C__ */

