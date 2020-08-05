#ifndef __PRMT_LANHOSTCONFMNGMT_C__
#define __PRMT_LANHOSTCONFMNGMT_C__

#include <stdio.h>
#include <string.h>
#include "prmt_lanhostconfmngmt.h"
#include "prmt_staticlease.h"
#include "bcm_param_api.h"
#include <bcmnvram.h>

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tLanHostConfMngmt[] = {
	/*(name,					type,			flag,	 				accesslist,	getvalue,				setvalue,				next_table,				sibling)*/
	{"IPRouters",				eCWMP_tSTRING,	CWMP_READ|CWMP_WRITE,	NULL,		get_LanHostConfMngmt,   set_LanHostConfMngmt,   NULL,       NULL},
	{"SubnetMask",				eCWMP_tSTRING,	CWMP_READ|CWMP_WRITE,	NULL,		get_LanHostConfMngmt,   set_LanHostConfMngmt,   NULL,       NULL},
///	{"DHCPServerConfigurable",			eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_LanHostConfMngmt,	set_LanHostConfMngmt,	NULL,		NULL},
	{"DHCPServerEnable",		eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,		get_LanHostConfMngmt,	set_LanHostConfMngmt,	NULL,		NULL},
	{"DHCPLeaseTime",			eCWMP_tINT,		CWMP_WRITE|CWMP_READ,	NULL,		get_LanHostConfMngmt,	set_LanHostConfMngmt,	NULL,		NULL},
///	{"DHCPStaticAddressNumberOfEntires",	eCWMP_tUINT,	CWMP_READ,	NULL,		get_LanHostConfMngmt,	NULL,					NULL,		NULL},
///	{"DHCPStaticAddress",		eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE,	NULL,		NULL,					StaticLeaseObj,			NULL,		NULL},
///	{"DHCPConditionalServingPool", eCWMP_tOBJECT,CWMP_WRITE|CWMP_READ, NULL,		NULL,					PoolObj,				NULL,					NULL},
	{"",						eCWMP_tNONE,	0,						NULL,		NULL,					NULL,					NULL,	    NULL}
};

/*
struct sCWMP_ENTITY tIpServingPool[] = {
	{"MinAddress",		eCWMP_tSTRING,
*/
int get_LanHostConfMngmt(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[128] = {0, };

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if (!nv_strcmp(lastname, "IPRouters")) {
		if (get_lanip(buf, sizeof(buf)))
			*data = strdup(buf);
		else
			return ERR_9002;

	} else if (!nv_strcmp(lastname, "SubnetMask")) {
		if (get_lanmask(buf, sizeof(buf)))
			*data = strdup(buf);
		else
			return ERR_9002;

	} else if (!nv_strcmp(lastname, "DHCPServerConfigurable")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "DHCPServerEnable")) {
		*data = booldup(get_dhcp());

	} else if (!nv_strcmp(lastname, "DHCPLeaseTime")) {
		nvram_safe_get_r("DHCP_LEASE_TIME", buf, sizeof(buf));
		if (STRLEN(buf))
			*data = intdup(atoi(buf));
		else
			*data = intdup(0);

	} else if (!nv_strcmp(lastname, "DHCPStaticAddressNumberOfEntries")) {
		empty_data(*type, data);
	} else
		return ERR_9005;

	return 0;
}

int set_LanHostConfMngmt(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
	char *buf=data;

	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;

	if (!nv_strcmp(lastname, "IPRouters")) {
		return set_lanip(buf);

	} else if (!nv_strcmp(lastname, "SubnetMask")) {
		return set_lanmask(buf);

	} else if (!nv_strcmp(lastname, "DHCPServerConfigurable")) {
	} else if (!nv_strcmp(lastname, "DHCPServerEnable")) {
		return set_dhcp(*(int *)buf);

	} else if (!nv_strcmp(lastname, "DHCPLeaseTime")) {
		char t[16] = "";
		snprintf(t, sizeof(t), "%u", *(int *)buf);
		nvram_set("DHCP_LEASE_TIME", t);
		return 1;

	} else
		return ERR_9005;

	return 0;
}
#endif /* __PRMT_LANHOSTCONFMNGMT_C__ */

