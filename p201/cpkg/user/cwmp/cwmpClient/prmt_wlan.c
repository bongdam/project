#ifndef __PRMT_WLAN_C__
#define __PRMT_WLAN_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_wlan.h"
#include "bcm_param_api.h"

typedef enum {en_false = 0, en_true = 1} boolean;

struct sCWMP_ENTITY tWLAN[] = {
	/*(name,				type,			flag,	 				accesslist,		getvalue,	setvalue,			next_table,	sibling)*/
	{"SSIDTxOverEnable",	eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,			get_WLAN,	set_WLAN,		NULL,			NULL},
	{"SSIDRxOverEnable",	eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,			get_WLAN,	set_WLAN,		NULL,			NULL},
	{"SSIDConnOverEnable",	eCWMP_tBOOLEAN,	CWMP_WRITE|CWMP_READ,	NULL,			get_WLAN,	set_WLAN,		NULL,			NULL},
	{"",										eCWMP_tNONE,			0,												NULL,			NULL,			NULL,				NULL,			NULL}
};

struct sCWMP_ENTITY	tWLANMONMAP[] = {
	{"0",						eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE|CWMP_LNKLIST,	NULL,		NULL,				NULL,			tWLAN,	NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

int WLANMonObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	int i;

	switch(type) {
	case eCWMP_tINITOBJ:
	{
		int max_wlan=MAXIDX * MAXSUBIDX;
		struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;

		for(i=0; i <max_wlan; i++) {
			if (create_Object(c, tWLANMONMAP, sizeof(tWLANMONMAP), 1, i+1)< 0)
				break;
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

int get_WLAN(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[256] = {0}, *ptr;
	int idx, wl_idx, wl_subidx;
	int res;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	snprintf(buf, sizeof(buf), "%s", name);
	ptr = strstr(buf, "WLAN.");
	if (ptr && STRLEN(ptr) > STRLEN("WLAN."))
		ptr += STRLEN("WLAN.");
	idx = atoi(ptr);

	get_wlan_idxes(idx, &wl_idx, &wl_subidx);

	if( nv_strcmp( lastname, "SSIDTxOverEnable" )==0 )
	{
		res = get_ssid_tx_over(wl_idx, wl_subidx);
		*data = booldup(res);
	}else if( nv_strcmp( lastname, "SSIDRxOverEnable")==0 )
	{
		res = get_ssid_rx_over(wl_idx, wl_subidx);
		*data = booldup(res);
	}else if( nv_strcmp( lastname, "SSIDConnOverEnable")==0 )
	{
		res = get_ssid_conn_over(wl_idx, wl_subidx);
		*data = booldup(res);
	}else{
		return ERR_9005;
	}

	return 0;
}

int set_WLAN(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char	*lastname = entity->name;
	char 	*val=data, buf[256];
	char	*ptr;
	int		idx, wl_idx, wl_subidx;
	
	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;

	snprintf(buf, sizeof(buf), "%s", name);
	ptr = strstr(buf, "WLAN.");
	if (ptr && STRLEN(ptr) > STRLEN("WLAN."))
		ptr += STRLEN("WLAN.");
	idx = atoi(ptr);

	get_wlan_idxes(idx, &wl_idx, &wl_subidx);

	if( nv_strcmp( lastname, "SSIDTxOverEnable" )==0 )
	{
		set_ssid_tx_over(*(int *)val, wl_idx, wl_subidx);
		return 0;
	}else if( nv_strcmp( lastname, "SSIDRxOverEnable" )==0 )
	{
		set_ssid_rx_over(*(int *)val, wl_idx, wl_subidx);
		return 0;
	}else if( nv_strcmp( lastname, "SSIDConnOverEnable" )==0 )
	{
		set_ssid_conn_over(*(int *)val, wl_idx, wl_subidx);
		return 0;
	}else
		return ERR_9005; 

	return 0;
}
#endif /* __PRMT_WLAN_C__ */
