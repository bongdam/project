#ifndef MAP_INIT_H
#define MAP_INIT_H

#include <stdio.h>
#include <stdlib.h>

#define READ_BUF_SIZE 50
#define MAP_CONFIG_2G (0)
#define MAP_CONFIG_5G (1)

struct config_info {
	unsigned char config_type;
	char *        ssid;
	char *        network_key;
	unsigned char network_type;
};

struct bss_info {
	char ssid[33];
	char network_key[64];
	int  network_type;
	int  is_enabled;
	int  encrypt_type;
};
////////////////////////////////////////////////////////////////////////////////
struct radio_info {
	//per radio config data
	unsigned char    radio_type;
	int              radio_channel;
	int              radio_channel_bonding;
	char             repeater_ssid[33];
	unsigned char    bss_nr;
	struct bss_info *bss_data;
};

struct mib_info {
	int                reg_domain;
	int                op_mode;
	int                map_role;
	char               device_name_buffer[30];
	int                map_configured_band;
	unsigned char      radio_nr;
	struct radio_info *radio_data;
};
////////////////////////////////////////////////////////////////////////////////

void multi_ap_app();
#endif
