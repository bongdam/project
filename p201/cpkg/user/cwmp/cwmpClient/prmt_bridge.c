#ifndef __PRMT_LIST_C__
#define __PRMT_LIST_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_bridge.h"
#include "bcm_param_api.h"

struct sCWMP_ENTITY tVLANTbl[] = {
	{"VLANEnable",			eCWMP_tBOOLEAN,	CWMP_READ|CWMP_WRITE,	NULL,		get_vlan,	set_vlan,		NULL,		NULL},
	{"VLANName",			eCWMP_tSTRING,	CWMP_READ|CWMP_WRITE,	NULL,		get_vlan,	set_vlan,		NULL,		NULL},
	{"VLANID",				eCWMP_tINT,		CWMP_READ|CWMP_WRITE,	NULL,		get_vlan,	set_vlan,		NULL,		NULL},
	{"",					eCWMP_tNONE,	0,			NULL,		NULL,		NULL,		NULL,		NULL}
};
struct sCWMP_ENTITY	tVLANMAP[] = {
	{"0",		eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE|CWMP_LNKLIST,	NULL,		NULL, 	NULL, tVLANTbl,	NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};
struct sCWMP_ENTITY tBridgeTbl[] = {
	/*(name,			type,			flag,	 	accesslist,	getvalue,	setvalue,	next_table,	sibling)*/
	{"BridgeKey",			eCWMP_tUINT,	CWMP_READ,				NULL,		get_bridge,		NULL,		NULL,		NULL},
	{"BridgeEnable",		eCWMP_tBOOLEAN,	CWMP_READ,				NULL,		get_bridge,		NULL,		NULL,		NULL},
	{"BridgeStatus",		eCWMP_tSTRING,	CWMP_READ,				NULL,		get_bridge,		NULL,		NULL,		NULL},
	{"BridgeName",			eCWMP_tSTRING,	CWMP_READ|CWMP_WRITE,	NULL,		get_bridge,		set_bridge,	NULL,		 NULL},
	{"VLANID",				eCWMP_tINT,		CWMP_READ|CWMP_WRITE,	NULL,		get_bridge,		set_bridge,	NULL,		NULL},
	{"BridgeStandard",		eCWMP_tSTRING,	CWMP_READ|CWMP_WRITE,	NULL,		get_bridge,		set_bridge,	NULL,		NULL},
	{"VLANNumberOfEntries",	eCWMP_tUINT,	CWMP_READ,				NULL,		get_bridge,		NULL,		NULL,		NULL},
	{"VLAN",				eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE,	NULL,		NULL,			VLANObj,	NULL,	NULL},
	{"",					eCWMP_tNONE,	0,			NULL,		NULL,		NULL,		NULL,		NULL}
};

struct sCWMP_ENTITY	tBRDGMAP[] = {
	{"0",		eCWMP_tOBJECT,	CWMP_READ|CWMP_WRITE|CWMP_LNKLIST,	NULL,		NULL, 	NULL, tBridgeTbl,	NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

int BridgeObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	int num = 1;
	struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;
	switch(type) {
	case eCWMP_tINITOBJ:
		create_Object(c, tBRDGMAP, sizeof(tBRDGMAP), 1, num);
		add_objectNum(name, num);
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

int VLANObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	int num;
	struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;
	switch(type) {
	case eCWMP_tINITOBJ:
		for (num = 0;num < 2;num++) 
			create_Object(c, tVLANMAP, sizeof(tVLANMAP), 1, num + 1);
		add_objectNum(name, num);
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

int get_bridge(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if ( nv_strcmp( lastname, "BridgeKey" )==0 ) {
		*data = uintdup(1);
	} else if ( nv_strcmp( lastname, "BridgeEnable")==0 ) {
		*data = booldup(1);
	} else if ( nv_strcmp( lastname, "BridgeStatus")==0 ) {
		*data = strdup("running");
	} else if ( nv_strcmp( lastname, "BridgeName")==0 ) {
		*data  = strdup("br0");
	} else if ( nv_strcmp( lastname, "VLANID")==0 ) {
		*data = uintdup(2);
	} else if ( nv_strcmp( lastname, "BridgeStandard")==0 ) {
		*data = strdup("\0");
	} else if (nv_strcmp( lastname, "VLANNumberOfEntries" )==0 ) {
		*data = uintdup(2);
	} else {
		return ERR_9005;
	}

	return 0;
}

int set_bridge(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;

	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;
	if( entity->type!=type ) return ERR_9006;

	if( nv_strcmp( lastname, "BridgeName")==0 ) {

	} else if ( nv_strcmp( lastname, "VLANID")==0 ) {

	} else if ( nv_strcmp( lastname, "BridgeStandard")==0 ) {

	} else {
		return ERR_9005;
	}

	return 0;
}

int get_vlan(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[128] = {0, };

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	if( nv_strcmp( lastname, "VLANEnable" )==0 ) {
		*data = booldup(1);
	} else if( nv_strcmp( lastname, "VLANName")==0 ) {
		if (strstr(name, "VLAN.1"))
			*data = strdup("vlan2");
		else
			*data = strdup("vlan1");
	} else if( nv_strcmp( lastname, "VLANID")==0 ) {
		*data = uintdup(2);
	} else {
		return ERR_9005;
	}

	return 0;
}

int set_vlan(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
	//char *buf=data;

	if( (name==NULL) || (data==NULL) || (entity==NULL)) return -1;

	if( entity->type!=type ) return ERR_9006;
	
	if ( nv_strcmp( lastname, "VLANEnable" )==0 ) {

	} else if( nv_strcmp( lastname, "VLANName")==0 ) {

	} else if( nv_strcmp( lastname, "VLANID")==0 ) {

	} else {
		return ERR_9005;
	}

	return 0;
}
#endif /* __PRMT_LIST_C__ */
