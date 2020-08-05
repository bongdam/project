#ifndef __PRMT_MNGMTSERVER_C__
#define __PRMT_MNGMTSERVER_C__
#include <string.h>
#include <bcmnvram.h>
#include "prmt_mngmtserver.h"
#include "bcm_param_api.h"

typedef enum {en_false = 0, en_true = 1} boolean;

char gParameterKey[32+1];

struct sCWMP_ENTITY tManagementServer[] =
{
	/*(name,								type,				flag,						accesslist,	getvalue,			setvalue,			next_table,	sibling)*/
///	{"URL",									eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"Username",							eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"Password",							eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"PeriodicInformEnable",				eCWMP_tBOOLEAN,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"PeriodicInformInterval",				eCWMP_tUINT,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"PeriodicInformTime",					eCWMP_tDATETIME,	CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
	{"ParameterKey",						eCWMP_tSTRING,		CWMP_READ|CWMP_DENY_ACT,	NULL,		getMngmntServer,	NULL,				NULL,		NULL},
	{"ConnectionRequestURL",				eCWMP_tSTRING,		CWMP_READ,					NULL,		getMngmntServer,	NULL,				NULL,		NULL},
///	{"ConnectionRequestUsername",			eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"ConnectionRequestPassword",			eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"UpgradesManaged",						eCWMP_tBOOLEAN,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"KickURL",								eCWMP_tSTRING,		CWMP_READ,					NULL,		getMngmntServer,	NULL,				NULL,		NULL},
///	{"DownloadProgressURL",					eCWMP_tSTRING,		CWMP_READ,					NULL,		getMngmntServer,	NULL,				NULL,		NULL},
	{"UDPConnectionRequestAddress",			eCWMP_tSTRING,		CWMP_READ,					NULL,		getMngmntServer,	NULL,				NULL,		NULL},
///	{"UDPConnectionRequestAddressNotifiLimit",	eCWMP_tUINT,	CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
	{"STUNEnable",							eCWMP_tBOOLEAN,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"STUNServerAddr",						eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"STUNServerPort",						eCWMP_tUINT,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"STUNUsername",						eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"STUNPassword",						eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"STUNMaximumKeepAlivePeriod",			eCWMP_tUINT,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"STUNMinimumKeepAlivePeriod",			eCWMP_tUINT,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"NATDetected",							eCWMP_tBOOLEAN,		CWMP_READ,					NULL,		getMngmntServer,	NULL,				NULL,		NULL},
///	{"ManageableDeviceNumOfEntries",		eCWMP_tUINT,		CWMP_READ,					NULL,		getMngmntServer,	NULL,				NULL,		NULL},
///	{"ManageableDeviceNotifiLimit",			eCWMP_tUINT,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"EnableCWMP",							eCWMP_tBOOLEAN,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
///	{"DefaultActiveNotifiThrottle",			eCWMP_tUINT,		CWMP_WRITE|CWMP_READ,		NULL,		getMngmntServer,	setMngmntServer,	NULL,		NULL},
	{"",									eCWMP_tNONE,		0,							NULL,		NULL,				NULL,				NULL,		NULL}
};

#define CHECK_PARAM_STR(str, min, max)  do { \
	int tmp; \
	if (!str) return ERR_9007; \
	tmp=STRLEN(str); \
	if ((tmp < min) || (tmp > max)) return ERR_9007; \
}	while (0)

#define CHECK_PARAM_NUM(input, min, max) if ( (input < min) || (input > max) ) return ERR_9007;

extern int MgmtSrvGetConReqURL(char *url, unsigned int size);
extern int MgmtSrvGetUDPConReqURL(char *url, unsigned int size);
extern void cwmpMgmtSetHPPeriod(int period);
extern void cwmpMgmtSetHPttl(int ttl);
extern int cwmpMgmtGetSTUNEnable(void);
extern int dnsQuery(char *domain, unsigned int *ip);
extern void cwmpMgmtSrvInformInterval();
extern int cwmpMgmtGetPeriodicInformInterval(void);
extern void cwmpMgmtSetSTUNEnable(int val);

void MgmtSrvSetParamKey(const char *key) {
//	gParameterKey[0]='\0';
	memset(gParameterKey, 0, sizeof(gParameterKey));
	if (key)
		strncpy(gParameterKey, key, sizeof(gParameterKey) -1);
}

int getMngmntServer(char *name, struct sCWMP_ENTITY *entity, int *type, void **data)
{
	char *lastname = entity->name;
	char buf[256] = {0, };
	char tmp[128] = {0, };
	unsigned int res = 0;
	struct in_addr dns_rslt;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL))
		return -1;

	dns_rslt.s_addr = 0;

	*type = entity->type;
	*data = NULL;

	if (nv_strcmp(lastname, "URL")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "Username")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "Password")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "PeriodicInformEnable")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "PeriodicInformInterval")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "PeriodicInformTime")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "ParameterKey")==0) {
		*data = strdup(gParameterKey);

	} else if (nv_strcmp(lastname, "ConnectionRequestURL")==0) {
		if (MgmtSrvGetConReqURL((char*)buf, sizeof(buf)))
			*data = strdup((char*)buf);

	} else if (nv_strcmp(lastname, "ConnectionRequestUsername")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "ConnectionRequestPassword")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "UpgradesManaged")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "KickURL")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "DownloadProgressURL")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "UDPConnectionRequestAddress")==0) {
		if (MgmtSrvGetUDPConReqURL((char*)buf, sizeof(buf)))
			*data = strdup((char*)buf);
		else
			*data = strdup("");

	} else if (nv_strcmp(lastname, "UDPConnectionRequestAddressNotifiLimit")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "STUNEnable")==0) {
		int res = cwmpMgmtGetSTUNEnable();
		*data = booldup(res);

	} else if (nv_strcmp(lastname, "STUNServerAddr")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "STUNServerPort")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "STUNUsername")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "STUNPassword")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "STUNMaximumKeepAlivePeriod")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "STUNMinimumKeepAlivePeriod")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "NATDetected")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "ManageableDeviceNumOfEntries")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "ManageableDeviceNotifiLimit")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "EnableCWMP")==0) {
		empty_data(*type, data);
	} else if (nv_strcmp(lastname, "DefaultActiveNotifiThrottle")==0) {
		empty_data(*type, data);
	} else
		return ERR_9005;

	return 0;
}
extern void cwmpMgmtConnReqPassword(const char *);

int setMngmntServer(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
	char *buf = data, tmp[128] = {0, };
	unsigned int pNum = 0;
	unsigned char byte;

	if( (name==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;

//	printf("[%s:%d] name is <%s>\n", __FUNCTION__, __LINE__, lastname);

	if (nv_strcmp(lastname, "URL")==0) {
	} else if (nv_strcmp(lastname, "Username")==0) {
	} else if (nv_strcmp(lastname, "Password")==0) {
	} else if (nv_strcmp(lastname, "PeriodicInformEnable")==0) {
	} else if (nv_strcmp(lastname, "PeriodicInformInterval")==0) {
	} else if (nv_strcmp(lastname, "PeriodicInformTime")==0) {
	} else if (nv_strcmp(lastname, "ConnectionRequestUsername")==0) {
	} else if (nv_strcmp(lastname, "ConnectionRequestPassword")==0) {
	} else if (nv_strcmp(lastname, "UpgradesManaged")==0) {
	} else if (nv_strcmp(lastname, "UDPConnectionRequestAddressNotifiLimit")==0) {
	} else if (nv_strcmp(lastname, "STUNEnable")==0) {
		pNum = *(unsigned int *)buf;
		CHECK_PARAM_NUM(pNum, 0, 1);
		cwmpMgmtSetSTUNEnable(pNum);

	} else if (nv_strcmp(lastname, "STUNServerAddr")==0) {
	} else if (nv_strcmp(lastname, "STUNServerPort")==0) {
	} else if (nv_strcmp(lastname, "STUNUsername")==0) {
	} else if (nv_strcmp(lastname, "STUNPassword")==0) {
	} else if (nv_strcmp(lastname, "STUNMaximumKeepAlivePeriod")==0) {
	} else if (nv_strcmp(lastname, "STUNMinimumKeepAlivePeriod")==0) {
	} else if (nv_strcmp(lastname, "ManageableDeviceNotifiLimit")==0) {
	} else if (nv_strcmp(lastname, "EnableCWMP")==0) {
	} else if (nv_strcmp(lastname, "DefaultActiveNotifiThrottle")==0) {
	} else
		return ERR_9005;

	return 0;
}

#endif /* __PRMT_MNGMTSERVER_C__ */

