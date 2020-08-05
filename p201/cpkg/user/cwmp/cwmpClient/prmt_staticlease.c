#ifndef __PRMT_STATICLEASE_C__
#define __PRMT_STATICLEASE_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>

#include <libytool.h>

#include "prmt_staticlease.h"
#include "bcm_param_api.h"

struct sCWMP_ENTITY tStaticLeaseInfo[] = {
	/*(name,		type,		flag,	 	accesslist,		getvalue,					setvalue,		next_table,	sibling)*/
	{"Enable",		eCWMP_tBOOLEAN,	CWMP_READ|CWMP_WRITE,	NULL,			get_StaticLeaseConf,		set_StaticLeaseConf,			NULL,			NULL},
	{"Chaddr",		eCWMP_tSTRING,	CWMP_READ|CWMP_WRITE,	NULL,			get_StaticLeaseConf,		set_StaticLeaseConf,			NULL,			NULL},
	{"Yiaddr",		eCWMP_tSTRING,	CWMP_READ|CWMP_WRITE,	NULL,			get_StaticLeaseConf,		set_StaticLeaseConf,			NULL,			NULL},
	{"",			eCWMP_tNONE,	0,		NULL,			NULL,						NULL,			NULL,			NULL}
};

struct sCWMP_ENTITY tStaticLeaseMAP[] = {
	{"0",			eCWMP_tOBJECT,  CWMP_READ|CWMP_WRITE|CWMP_LNKLIST,  NULL,       NULL,               NULL,           tStaticLeaseInfo,  NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

static int remove_item_from_lease_tbl(int idx, int *MaxInstNum)
{
	char key[32] = {0, };
	char buf[64] = {0, };
	int i = 0;

	for (i = (idx + 1); i <= *MaxInstNum; i++) {
		memset(key, 0, sizeof(key));
		memset(buf, 0, sizeof(buf));

		snprintf(key, sizeof(key), "DHCPRSVDIP_TBL%d", i);
		nvram_safe_get_r(key, buf, sizeof(buf));
		snprintf(key, sizeof(key), "DHCPRSVDIP_TBL%d", i-1);
		nvram_set(key, buf);
	}

	memset(key, 0, sizeof(key));
	memset(buf, 0, sizeof(buf));

	snprintf(key, sizeof(key), "DHCPRSVDIP_TBL%d", *MaxInstNum);
	//nvram_unset(key);
	nvram_set(key, "");

	snprintf(buf, sizeof(buf), "%d", --(*MaxInstNum));
	nvram_set("DHCPRSVDIP_TBL_NUM", buf);
	return 0;
}

static int get_lease_values_from_nvram(char *src, char *mac, char *ip, char *en)
{
	char *arg[3];
	int ret = 0;

	//DHCPRSVDIP_TBL2=94fbb2004350,192.168.123.188,1
	ret = ystrargs(src, arg, 3, ",", 1);
	if (ret != 3)
		return -1;

#if 0
	if (ret < 3) {
		if (idx == 1 && cur_tbl_cnt == 1) {
			//Just do it!!
		} else {
			snprintf(t, 3, "%d", --cur_tbl_cnt);
			nvram_set("DHCPRSVDIP_TBL_NUM", t);
			return ERR_9005;
		}
	}
#endif

	//arg[0] : mac or ""
	//arg[1] : ipaddr or ""
	//arg[2] : 1 / 0 or ""

	if (arg[0] != NULL && STRLEN(arg[0]) > 0) {
		fprintf(stderr, "arg[0] value : %s(%d)\n", arg[0], STRLEN(arg[0]));
		strncpy(mac, arg[0], STRLEN(arg[0]));
		mac[STRLEN(arg[0])] = '\0';
	} else {
		mac[0] = '\0';
	}

	if (arg[1] != NULL && STRLEN(arg[1]) > 0) {
		fprintf(stderr, "arg[1] value : %s(%d)\n", arg[1], STRLEN(arg[1]));
		strncpy(ip, arg[1], STRLEN(arg[1]));
		ip[STRLEN(arg[1])] = '\0';
	} else {
		ip[0] = '\0';
	}

	if (arg[2] != NULL && STRLEN(arg[2]) > 0) {
		fprintf(stderr, "arg[2] value : %s(%d)\n", arg[2], STRLEN(arg[2]));
		strncpy(en, arg[2], STRLEN(arg[2]));
		en[STRLEN(arg[2])] = '\0';
	} else {
		en[0] = '\0';
	}

	return 0;
}

int StaticLeaseObj(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	unsigned int i;
	char buf[128] = {0, };
	char key[32] = {0, };
	static int MaxInstNum=0;
	int ret;
	int num;

	switch(type) {
	case eCWMP_tINITOBJ:
	{
		struct sCWMP_ENTITY **c = (struct sCWMP_ENTITY **)data;

		if (IS_BRIDGE_MODE) {
			num = 0;
			return 0;
		}

		num = atoi(nvram_safe_get("DHCPRSVDIP_TBL_NUM"));

		for (i = 0; i < num && i < 20; i++) {
			snprintf(key, sizeof(key), "DHCPRSVDIP_TBL%d", i + 1);
			if (nvram_get_r(key, buf, sizeof(buf)) != NULL) {
				ret = create_Object(c, tStaticLeaseMAP, sizeof(tStaticLeaseMAP), 1, i + 1);
				MaxInstNum++;

				if (ret < 0)
					break;
			}
		}
		add_objectNum(name, i);
		return 0;
	}
	case eCWMP_tADDOBJ:
		if (IS_BRIDGE_MODE)
			return 0;

		if (MaxInstNum++ < 20)
			add_Object( name, &entity->next_table,  tStaticLeaseMAP, sizeof(tStaticLeaseMAP), data );
		else
			return -1;

		snprintf(buf, sizeof(buf), "%d", *(int *)data);
		nvram_set("DHCPRSVDIP_TBL_NUM", buf);
//		memcpy(data, &MaxInstNum, sizeof(int));
		return 0;
	case eCWMP_tDELOBJ:
		if( (name==NULL) || (entity==NULL) || (data==NULL) ) return -1;

		if (IS_BRIDGE_MODE)
			return 0;

		ret = del_Object( name, &entity->next_table, *(int*)data );
		if (ret != 0)
			return -1;

		num = *(int *)data;

		remove_item_from_lease_tbl(num, &MaxInstNum);

		return 1;

	case eCWMP_tUPDATEOBJ:
		return 0;

	default:
		break;
	}

	return -1;
}

int get_StaticLeaseConf(char *name, struct sCWMP_ENTITY *entity, int* type, void **data)
{
	char *lastname = entity->name;
	char buf[128] = {0, };
	char tmp[64] = {0, }, *deli="DHCPStaticAddress.";
	char *ptr;
	int idx = 0;
	int ret = 0;

	char key[32] = {0, };
	char mac[17] = {0, };
	char ip[45] = {0, };
	char en[4] = {0, };

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

	if (idx <= 0 || idx > atoi(nvram_safe_get("DHCPRSVDIP_TBL_NUM")))
		return ERR_9005;
	//idx -= 1;

	snprintf(key, sizeof(key), "DHCPRSVDIP_TBL%d", idx);

	nvram_safe_get_r(key, tmp, sizeof(tmp));

	get_lease_values_from_nvram(tmp, mac, ip, en);

	if (!nv_strcmp(lastname, "Chaddr")) {
		add_colon_to_macaddr(buf, mac, sizeof(buf), UPPER);
		*data = strdup(buf);
	}
	else if (!nv_strcmp(lastname, "Enable")) {
		ret = atoi(en);
		if (ret != 1 && ret != 0)
			return ERR_9002;

		*data = booldup(ret);
	}
	else if (!nv_strcmp(lastname, "Yiaddr")) {
		*data = strdup(ip);
	} else {
		return ERR_9005;
	}

	return 0;
}

int set_StaticLeaseConf(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
	char *val = data;
	char tmp[64] = {0, }, *deli="DHCPStaticAddress.";
	char *ptr = NULL;
	int idx = 0;

	char key[32] = {0, };
	char org_val[64] = {0, };
	char new_val[128] = {0, };
	int cur_tbl_cnt = 0;

	char mac[17] = {0, };
	char ip[45] = {0, };
	char en[4] = {0, };

	if( (name==NULL) || (data==NULL) || (entity==NULL) ) {
		return -1;
	}

	if (type != entity->type)
		return ERR_9006;

	if (IS_BRIDGE_MODE)
		return 0;

	ptr = strstr(name, deli);
	if (ptr && STRLEN(ptr)>STRLEN(deli)) {
		ptr += STRLEN(deli);
		idx = atoi(ptr);
	}

	ptr = NULL;

	cur_tbl_cnt = atoi(nvram_safe_get("DHCPRSVDIP_TBL_NUM"));
	if (idx <= 0 || idx > cur_tbl_cnt)
		return ERR_9005;

	//idx -= 1;

	snprintf(key, sizeof(key), "DHCPRSVDIP_TBL%d", idx);

	nvram_safe_get_r(key, org_val, sizeof(org_val));

	if (STRLEN(org_val) < 1) {
		nvram_set(key, ",,");
		strncpy(org_val, ",,", 2);
		org_val[2] = '\0';
	}

	get_lease_values_from_nvram(org_val, mac, ip, en);

	if (!nv_strcmp(lastname, "Chaddr")) {
		if (STRLEN(val) > 17)
			return ERR_9007;

		remove_colon_from_macaddr(tmp, val, sizeof(tmp), LOWER);

		snprintf(new_val, sizeof(new_val), "%s,%s,%s", tmp, ip, en);
		nvram_set(key, new_val);
		return 1;
	}
	else if (!nv_strcmp(lastname, "Enable")) {
		if (*(int *)val != 0 && *(int *)val != 1)
			return ERR_9007;

		snprintf(new_val, sizeof(new_val), "%s,%s,%d", mac, ip, *(int *)val);
		nvram_set(key, new_val);
		return 1;
	}
	else if (!nv_strcmp(lastname, "Yiaddr")) {
		if (STRLEN(val) > 45 || inet_addr(val) == INADDR_NONE)
		return ERR_9007;

		snprintf(new_val, sizeof(new_val), "%s,%s,%s", mac, val, en);
		nvram_set(key, new_val);
		return 1;
	} else
		return ERR_9005;

	return 0;
}
#endif
