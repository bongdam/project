#ifndef __PRMT_LIST_C__
#define __PRMT_LIST_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_list.h"

struct sCWMP_ENTITY tList[] = {
	/*(name,			type,			flag,	 	accesslist,	getvalue,	setvalue,	next_table,	sibling)*/
	{"FilterEnable",	eCWMP_tBOOLEAN,	CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"Policy",			eCWMP_tSTRING,	CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"Direction",		eCWMP_tSTRING,	CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"URL",				eCWMP_tSTRING,	CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"Protocol",		eCWMP_tSTRING,	CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"SrcMACAddr",		eCWMP_tSTRING,	CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"SrcIPAddr",		eCWMP_tSTRING,	CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"SrcPort",			eCWMP_tINT,		CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"DestMACAddr",		eCWMP_tSTRING,	CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"DestIPAddr",		eCWMP_tSTRING,	CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"DestPort",		eCWMP_tINT,		CWMP_READ,	NULL,		get_List,	NULL,		NULL,		NULL},
	{"",				eCWMP_tNONE,	0,			NULL,		NULL,		NULL,		NULL,		NULL}
};

int get_List(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	unsigned char buf[256] = {0};
	char t[64], key[32];
	int idx=0;
	char *ptr;

	if( (name==NULL) || (type==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	*type = entity->type;
	*data = NULL;

	snprintf(buf, sizeof(buf), "%s", name);
	ptr = strrchr(buf, '.');

	if (ptr)
		*ptr = 0;
			
	ptr = strrchr(buf, '.');
	if (ptr && STRLEN(ptr) > 1)
		idx = atoi(ptr+1);
	
	if (idx <= 0 || idx > 16)
		return ERR_9005;

	snprintf(key, sizeof(key), "acs_fw%d", idx-1);

	if( nv_strcmp( lastname, "FilterEnable" )==0 )
	{
		nvram_safe_get_r("fw_disable", buf, sizeof(buf));
		*data = booldup( atoi(buf) );
	}else if( nv_strcmp( lastname, "Policy")==0 )
	{
		nvram_safe_get_r(key, buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "Direction")==0 )
	{
		char *tok1, *tok2;
		
		nvram_safe_get_r(key, buf, sizeof(buf));
		
		tok1 = buf;
		tok2 = strsep(&tok1, ",");
		
		if (tok2 == NULL)
			return ERR_9007;

		*data = strdup(tok2);
	}else if (nv_strcmp( lastname, "URL" )==0 )
	{
		nvram_safe_get_r(key, buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "Protocol")==0 )
	{
		nvram_safe_get_r(key, buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "SrcMACAddr")==0 )
	{
		nvram_safe_get_r(key, buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "SrcIPAddr")==0 )
	{
/*
		char *tok1, *tok2;
		
		nvram_safe_get_r(key, buf, sizeof(buf));
		
		tok1 = buf;
		tok2 = strsep(&tok1, ",");	// direction

		if (tok2 == NULL)
			return ERR_9007;

		if (!nv_strcmp(tok2, "in")) {
			tok2 = strsep(&tok1, ",");	// ip
		} else {
		}
		*data = strdup(tok2);
*/
	}else if( nv_strcmp( lastname, "SrcPort")==0 )
	{
/*
		char *tok1, *tok2;
		
		nvram_safe_get_r(key, buf, sizeof(buf));
		
		tok1 = buf;
		tok2 = strsep(&tok1, ",");	// direction
		tok2 = strsep(&tok1, ",");	// ip
		tok2 = strsep(&tok1, ",");	// port
		
		if (tok2 == NULL)
			return ERR_9007;

		*data = intdup( atoi(tok2) );
*/
	}else if( nv_strcmp( lastname, "DestMACAddr")==0 )
	{
		nvram_safe_get_r(key, buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "DestIPAddr")==0 )
	{
		nvram_safe_get_r(key, buf, sizeof(buf));
		*data = strdup( (char*)buf );
	}else if( nv_strcmp( lastname, "DestPort")==0 )
	{
		nvram_safe_get_r(key, buf, sizeof(buf));
		*data = intdup( (int)buf );
	}else{
		return ERR_9005;
	}

	return 0;
}
#endif /* __PRMT_LIST_C__ */
