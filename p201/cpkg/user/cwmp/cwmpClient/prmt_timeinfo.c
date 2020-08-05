#ifndef __PRMT_TIMEINFO_C__
#define __PRMT_TIMEINFO_C__

#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>

#include <bcmnvram.h>
#include "parameter_api.h"
#include "prmt_timeinfo.h"
#include "bcm_param_api.h"

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tTimeInfo[] =
{
	//(name,						type,				flag,	 				accesslist,	getvalue,		setvalue,		next_table,	sibling)
	{"NTPServer1",					eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,		NULL},
	{"NTPServer2",					eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,		NULL},
	{"NTPServer3",					eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,		NULL},
	{"NTPServer4",					eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,		NULL},
	{"NTPServer5",					eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,		NULL},
	{"CurrentLocalTime",			eCWMP_tDATETIME,	CWMP_READ,				NULL,		get_TimeInfo,	NULL,			NULL,		NULL},
///	{"LocalTimeZone",				eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,       NULL},
	{"LocalTimeZoneName",			eCWMP_tSTRING,		CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,       NULL},
///	{"DaylightSavingsUsed",			eCWMP_tBOOLEAN,  	CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,		NULL},
///	{"DaylightSavingsStart",		eCWMP_tDATETIME, 	CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,		NULL},
///	{"DaylightSavingsEnd",			eCWMP_tDATETIME, 	CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,		NULL},
///	{"Enable",						eCWMP_tBOOLEAN,  	CWMP_WRITE|CWMP_READ,	NULL,		get_TimeInfo,	set_TimeInfo,	NULL,		NULL},
///	{"Status",						eCWMP_tSTRING,  	CWMP_READ,				NULL,		get_TimeInfo,	NULL,			NULL,		NULL},
	{"",							eCWMP_tNONE,		0,						NULL,		NULL,			NULL,			NULL,		NULL}
};

int get_TimeInfo(char *name, struct sCWMP_ENTITY *entity, int *type, void **data)
{
	char *lastname = entity->name;
	char buf[256] = {0, };

	if ((name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL))
		return -1;

	*type = entity->type;
	*data = NULL;

	if (!nv_strcmp(lastname, "NTPServer1")) {
		//APACRTL-339
		get_ntp_server(buf, sizeof(buf), 1);
		*data = strdup((char*)buf);

	} else if (!nv_strcmp(lastname, "NTPServer2")) {
		//APACRTL-339
		get_ntp_server(buf, sizeof(buf), 2);
		*data = strdup((char*)buf);

	} else if (!nv_strcmp(lastname, "NTPServer3")) {
		//APACRTL-339
		get_ntp_server(buf, sizeof(buf), 3);
		*data = strdup((char*)buf);

	} else if (!nv_strcmp(lastname, "NTPServer4")) {
		//APACRTL-339
		get_ntp_server(buf, sizeof(buf), 4);
		*data = strdup((char*)buf);

	} else if (!nv_strcmp(lastname, "NTPServer5")) {
		//APACRTL-339
		get_ntp_server(buf, sizeof(buf), 5);
		*data = strdup((char*)buf);

	} else if (!nv_strcmp(lastname, "CurrentLocalTime")) {
		time_t tt;
		tt = time(NULL);
		*data = timedup(tt);

	} else if (!nv_strcmp(lastname, "LocalTimeZone")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "LocalTimeZoneName")) {
		get_ntp_tz(buf, sizeof(buf));
		*data = strdup((char*)buf);

	} else if (!nv_strcmp(lastname, "DaylightSavingsUsed")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "DaylightSavingsStart")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "DaylightSavingsEnd")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "Enable")) {
		empty_data(*type, data);
	} else if (!nv_strcmp(lastname, "Status")) {
		empty_data(*type, data);
	} else
		return ERR_9005;

	return 0;
}

int set_TimeInfo(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
	char *buf = data;
	int len = 0;

	if ((name==NULL) || (data==NULL) || (entity==NULL))
		return -1;

	if (entity->type!=type)
		return ERR_9006;

	if (!nv_strcmp(lastname, "NTPServer1")) {
		//APACRTL-339
		set_ntp_server(buf, 1);
		return 1;

	} else if (!nv_strcmp(lastname, "NTPServer2")) {
		//APACRTL-339
		set_ntp_server(buf, 2);
		return 1;

	} else if (!nv_strcmp(lastname, "NTPServer3")) {
		//APACRTL-339
		set_ntp_server(buf, 3);
		return 1;

	} else if (!nv_strcmp(lastname, "NTPServer4")) {
		//APACRTL-339
		set_ntp_server(buf, 4);
		return 1;

	} else if (!nv_strcmp(lastname, "NTPServer5")) {
		//APACRTL-339
		set_ntp_server(buf, 5);
		return 1;

	} else if (!nv_strcmp(lastname, "LocalTimeZone")) {
	} else if (!nv_strcmp(lastname, "LocalTimeZoneName")) {
		set_ntp_tz(buf);
		return 1;

	} else if (!nv_strcmp(lastname, "DaylightSavingsUsed")) {
	} else if (!nv_strcmp(lastname, "DaylightSavingsStart")) {
	} else if (!nv_strcmp(lastname, "DaylightSavingsEnd")) {
	} else if (!nv_strcmp(lastname, "Enable")) {
	} else
		return ERR_9005;

	return 0;
}

#endif /* __PRMT_TIMEINFO_C__ */

