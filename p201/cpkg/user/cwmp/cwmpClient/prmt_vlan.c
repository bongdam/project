#ifndef __PRMT_VLAN_C__
#define __PRMT_VLAN_C__

#include <stdio.h>
#include <string.h>
#include <bcmnvram.h>
#include "prmt_vlan.h"

typedef enum { en_false = 0, en_true = 1 } boolean;

struct sCWMP_ENTITY tVLAN[] = {
	/*(name,     type,   flag, accesslist,  getvalue,  setvalue,  next_table,  sibling) */
	{"VLANEnable", eCWMP_tBOOLEAN, CWMP_WRITE | CWMP_READ, NULL, get_VLAN, set_VLAN, NULL, NULL},
	{"VLANName", eCWMP_tSTRING, CWMP_WRITE | CWMP_READ, NULL, get_VLAN, set_VLAN, NULL, NULL},
	{"VLANID", eCWMP_tINT, CWMP_WRITE | CWMP_READ, NULL, get_VLAN, set_VLAN, NULL, NULL},
	{"", eCWMP_tNONE, 0, NULL, NULL, NULL, NULL, NULL}
};

int get_VLAN(char *name, struct sCWMP_ENTITY *entity, int *type, void **data)
{
	char *lastname = entity->name;
	char buf[256] = { 0 };

	if ((name == NULL) || (type == NULL) || (data == NULL) || (entity == NULL))
		return -1;

	*type = entity->type;
	*data = NULL;

	if (nv_strcmp(lastname, "VLANEnable") == 0) {
		cwmp_cfg_get(CWMP_VLAN_ENABLE, (void *)buf, sizeof(buf));
		*data = booldup(atoi(buf));
	} else if (nv_strcmp(lastname, "VLANName") == 0) {
		cwmp_cfg_get(CWMP_VLAN_NAME, (void *)buf, sizeof(buf));
		*data = strdup((char *)buf);
	} else if (nv_strcmp(lastname, "VLANID") == 0) {
		cwmp_cfg_get(CWMP_VLAN_ID, (void *)buf, sizeof(buf));
		*data = intdup(atoi(buf));
	} else
		return ERR_9005;

	return 0;
}

int set_VLAN(char *name, struct sCWMP_ENTITY *entity, int type, void *data)
{
	char *lastname = entity->name;
	char *buf = data;
	int len = 0;

	if ((name == NULL) || (data == NULL) || (entity == NULL))
		return -1;
	if (entity->type != type)
		return ERR_9006;

	if (nv_strcmp(lastname, "VLANEnable") == 0) {
		if (buf)
			len = STRLEN(buf);
		if (len == 0)
			cwmp_cfg_set(CWMP_VLAN_ENABLE, (void *)"", 0);
		if (len < 64)
			cwmp_cfg_set(CWMP_VLAN_ENABLE, (void *)buf, len);
		else
			return ERR_9007;
		return 0;
	} else if (nv_strcmp(lastname, "VLANName") == 0) {
		if (buf)
			len = STRLEN(buf);
		if (len == 0)
			cwmp_cfg_set(CWMP_VLAN_NAME, (void *)"", 0);
		else if (len < 64)
			cwmp_cfg_set(CWMP_VLAN_NAME, (void *)buf, len);
		else
			return ERR_9007;
		return 0;
	} else if (nv_strcmp(lastname, "VLANID") == 0) {
		if (buf)
			len = STRLEN(buf);
		if (len == 0)
			cwmp_cfg_set(CWMP_VLAN_ID, (void *)"", 0);
		else if (len < 64)
			cwmp_cfg_set(CWMP_VLAN_ID, (void *)buf, len);
		else
			return ERR_9007;
		return 0;
	} else
		return ERR_9005;

	return 0;
}
#endif	/* __PRMT_VLAN_C__ */
