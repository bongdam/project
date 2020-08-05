#ifndef __HOLEPUNCHING_VALUE__
#define __HOLEPUNCHING_VALUE__

#include "apmib.h"

char *holepunch_dv_get_value(char *name);
void holepunch_dv_set_value(char *name, char *value);
char *holepunch_nv_get_value(char *name);

typedef struct {
	char *name;
	char *nv_name;
} nv_variable;

typedef struct {
	char *name;
	char *dv_name;
} dv_variable;

typedef enum {
    wlan0_disable,
    wlan0_voip_disable,
    wlan0_t_wifi_disable,
    wlan0_anyway_disable,
    wlan0_ratelimit,
    wlan0_voip_ratelimit,
    wlan0_t_wifi_ratelimit,
    wlan0_anyway_ratelimit,
    wlan1_disable,
    wlan1_voip_disable,
    wlan1_t_wifi_disable,
    wlan1_multi_disable,
    wlan1_ratelimit,
    wlan1_voip_ratelimit,
    wlan1_t_wifi_ratelimit,
    wlan1_multi_ratelimit
} MIBS;

void holepunch_nv_set_value(MIBS interface, char *value);

static dv_variable dv_name_tbl[] = {
	{"dv_hole_enable", 					"x_holepunch_enabled"},
	{"dv_holepunch_control_server", 	"x_holepunch_cserver" },
	{"dv_holepunch_control_server_port","x_holepunch_cport" },
	{"dv_holepunch_dbg",				"x_holepunch_dbg" },
	{"dv_holepunch_control_interval",	"x_holepunch_control_interval" },
	{NULL, NULL}
};

static nv_variable nv_name_tbl[] = {
	{"nv_wan_mac", 					"HW_NIC1_ADDR" },
	{"nv_5G_mac", 					"HW_WLAN0_WLAN_ADDR" },
	{"nv_2.4G_mac", 				"HW_WLAN1_WLAN_ADDR" },
	{"nv_5G_disabled",				"WLAN0_WLAN_DISABLED" },
	{"nv_2.4G_disabled", 			"WLAN1_WLAN_DISABLED" },
/*	{"nv_5G_voip_disabled",			"WLAN0_VAP0_WLAN_DISABLED" },
	{"nv_5G_t_wifi_disabled", 		"WLAN0_VAP1_WLAN_DISABLED" },
	{"nv_5G_anyway_disabled",		"WLAN0_VAP2_WLAN_DISABLED" },*/
	{"nv_5G_main_ratelimit",		"WLAN0_TX_RESTRICT" },
/*	{"nv_5G_voip_ratelimit",		"WLAN0_VAP0_TX_RESTRICT" },
	{"nv_5G_t_wifi_ratelimit",		"WLAN0_VAP1_TX_RESTRICT" },
	{"nv_5G_anyway_ratelimit",		"WLAN0_VAP2_TX_RESTRICT" },*/
	{"nv_2.4G_voip_disabled", 		"WLAN1_VAP0_WLAN_DISABLED" },
	{"nv_2.4G_t_wifi_disabled", 	"WLAN1_VAP1_WLAN_DISABLED" },
/*	{"nv_2.4G_anyway_disabled",		"WLAN1_VAP2_WLAN_DISABLED" },*/
	{"nv_2.4G_multi_disabled", 		"WLAN1_VAP3_WLAN_DISABLED" },
	{"nv_2.4G_main_ratelimit",		"WLAN1_TX_RESTRICT" },
	{"nv_2.4G_voip_ratelimit",		"WLAN1_VAP0_TX_RESTRICT" },
	{"nv_2.4G_t_wifi_ratelimit",	"WLAN1_VAP1_TX_RESTRICT" },
/*	{"nv_2.4G_anyway_ratelimit",	"WLAN1_VAP2_TX_RESTRICT" },*/
	{"nv_2.4G_multi_ratelimit",		"WLAN1_VAP3_TX_RESTRICT" },
	{"nv_opmode", 					"OP_MODE" },
	{"nv_5G_ssid", 					"WLAN0_SSID" },
/*	{"nv_5G_void_ssid", 			"WLAN0_VAP0_SSID" },
	{"nv_5G_t_wifi_ssid", 			"WLAN0_VAP1_SSID" },
	{"nv_5G_anyway_ssid", 			"WLAN0_VAP2_SSID" },*/
	{"nv_2.4G_ssid",				"WLAN1_SSID" },
	{"nv_2.4G_void_ssid", 			"WLAN1_VAP0_SSID" },
	{"nv_2.4G_t_wifi_ssid", 		"WLAN1_VAP1_SSID" },
/*	{"nv_2.4G_anyway_ssid", 		"WLAN1_VAP2_SSID" },*/
	{"nv_2.4G_multi_ssid",	 		"WLAN1_VAP3_SSID" },
	{"nv_admin_pw_init", 			"x_USER_PASSWORD"},
	{NULL, NULL}
};

nv_variable *nv_rename_value();
dv_variable *dv_rename_value();
void save_change_status();
#endif
