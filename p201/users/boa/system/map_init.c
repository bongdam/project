#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>

#include "apmib.h"
#include "map_init.h"
#include "sys_utility.h"

void _writeToConfig(FILE *fp, unsigned char config_nr, char **config_array)
{
	int i;
	for (i = 0; i < config_nr; i++) {
		fprintf(fp, "%s", config_array[i]);
		// free(config_array[i]);
		if (i < (config_nr - 1)) {
			fprintf(fp, ",");
		} else {
			fprintf(fp, "\n");
		}
	}
}

void _writeToConfig_dec(FILE *fp, unsigned char config_nr, unsigned char *config_array)
{
	int i;
	for (i = 0; i < config_nr; i++) {
		fprintf(fp, "%d", config_array[i]);
		if (i < (config_nr - 1)) {
			fprintf(fp, ",");
		} else {
			fprintf(fp, "\n");
		}
	}
}

void _read_mib_to_config(struct mib_info *mib_data)
{
	if (NULL == mib_data) {
		return 1;
	}

	apmib_get(MIB_MAP_DEVICE_NAME, (void *)mib_data->device_name_buffer);

	apmib_get(MIB_MAP_CONFIGURED_BAND, (void *)&mib_data->map_configured_band);

	apmib_get(MIB_HW_REG_DOMAIN, (void *)&mib_data->reg_domain);

	apmib_get(MIB_MAP_CONTROLLER, (void *)&mib_data->map_role);

	apmib_get(MIB_OP_MODE, (void *)&mib_data->op_mode);

	int i = 0, j = 0;

	if (NULL != mib_data->radio_data) {
		return 1;
	}

	for (i = 0; i < 2; i++) {
		mib_data->radio_nr += 1;
		mib_data->radio_data               = (struct radio_info *)realloc(mib_data->radio_data, sizeof(struct radio_info) * mib_data->radio_nr);
		mib_data->radio_data[i].bss_nr     = 0;
		mib_data->radio_data[i].bss_data   = NULL;
		mib_data->radio_data[i].radio_type = 0xFF;

		if (0 == i) {
			mib_data->radio_data[i].radio_type = MAP_CONFIG_5G;
			if (!apmib_get(MIB_REPEATER_SSID1, (void *)mib_data->radio_data[i].repeater_ssid)) {
				printf("Error reading mib in update_config_file!\n");
				return 0;
			}
		} else if (1 == i) {
			mib_data->radio_data[i].radio_type = MAP_CONFIG_2G;
			if (!apmib_get(MIB_REPEATER_SSID2, (void *)mib_data->radio_data[i].repeater_ssid)) {
				printf("Error reading mib in update_config_file!\n");
				return 0;
			}
		}

		wlan_idx  = i;
		vwlan_idx = 0;

		if (!apmib_get(MIB_WLAN_CHANNEL, (void *)&mib_data->radio_data[i].radio_channel)) {
			printf("Error reading mib in update_config_file!\n");
			return 0;
		}

		if (!apmib_get(MIB_WLAN_CHANNEL_BONDING, (void *)&mib_data->radio_data[i].radio_channel_bonding)) {
			printf("Error reading mib in update_config_file!\n");
			return 0;
		}

		for (j = 0; j < 6; j++) {
			mib_data->radio_data[i].bss_nr += 1;
			mib_data->radio_data[i].bss_data = (struct bss_info *)realloc(mib_data->radio_data[i].bss_data, sizeof(struct bss_info) * mib_data->radio_data[i].bss_nr);

			vwlan_idx = j;

			if (!apmib_get(MIB_WLAN_WLAN_DISABLED, (void *)&mib_data->radio_data[i].bss_data[j].is_enabled)) {
				printf("Error reading mib in update_config_file!\n");
				return 0;
			}

			mib_data->radio_data[i].bss_data[j].is_enabled = !mib_data->radio_data[i].bss_data[j].is_enabled;

			if (!apmib_get(MIB_WLAN_SSID, (void *)mib_data->radio_data[i].bss_data[j].ssid)) {
				printf("Error reading mib in update_config_file!\n");
				return 0;
			}
			//Insert dummy data for empty SSID
			if (0 == strlen(mib_data->radio_data[i].bss_data[j].ssid)) {
				// printf("read mib of ssid is empty, set dummy value...\n");
				char dumssid[10] = "dummyssid";
				strcpy(mib_data->radio_data[i].bss_data[j].ssid, dumssid);
			}

			if (!apmib_get(MIB_WLAN_MAP_BSS_TYPE, (void *)&mib_data->radio_data[i].bss_data[j].network_type)) {
				printf("Error reading mib in update_config_file!\n");
				return 0;
			}

			if (!apmib_get(MIB_WLAN_ENCRYPT, (void *)&mib_data->radio_data[i].bss_data[j].encrypt_type)) {
				printf("Error reading mib in update_config_file!\n");
				return 0;
			}

			if (!apmib_get(MIB_WLAN_WPA_PSK, (void *)mib_data->radio_data[i].bss_data[j].network_key)) {
				printf("Error reading mib in update_config_file!\n");
				return 0;
			}
			//Insert dummy data for empty PSK
			if (0 == mib_data->radio_data[i].bss_data[j].encrypt_type) {
				//printf("read mib[wlan%d_vap%d] of network_key is empty, set dummy value...\n", i, j);
				char dumkey[10] = "dummykey";
				strcpy(mib_data->radio_data[i].bss_data[j].network_key, dumkey);
			}
		}
	}
}

void _fill_config_data(struct mib_info *mib_data, struct config_info **config_data, unsigned char *config_nr)
{
	int  i, j;
	int  val;
	char buffer[100];
	for (i = 0; i < mib_data->radio_nr; i++) {
		for (j = 0; j < mib_data->radio_data[i].bss_nr; j++) {
			struct bss_info *bss_data = &mib_data->radio_data[i].bss_data[j];
			//if interface was disabled
			if (!bss_data->is_enabled && 0 == j) {
				(*config_nr)++;
				*config_data                                = (struct config_info *)realloc(*config_data, *config_nr * sizeof(struct config_info));
				(*config_data)[*config_nr - 1].config_type  = mib_data->radio_data[i].radio_type;
				(*config_data)[*config_nr - 1].ssid         = "TEARDOWN";
				(*config_data)[*config_nr - 1].network_key  = "invalidkey";
				(*config_data)[*config_nr - 1].network_type = 0x10; // TEAR_DOWN
			}
			//if enabled
			if (bss_data->is_enabled) {
				//wisp bug fix
				if (128 == bss_data->network_type) {
				// if (128 == bss_data->network_type && mib_data->op_mode == WISP_MODE) {
					continue;
				}
				(*config_nr)++;
				*config_data                                = (struct config_info *)realloc(*config_data, *config_nr * sizeof(struct config_info));
				(*config_data)[*config_nr - 1].config_type  = mib_data->radio_data[i].radio_type;
				(*config_data)[*config_nr - 1].ssid         = bss_data->ssid;
				(*config_data)[*config_nr - 1].network_key  = bss_data->network_key;
				(*config_data)[*config_nr - 1].network_type = (unsigned char)bss_data->network_type;
			}
		}
	}
}

void _update_config(struct mib_info *mib_data, char *config_file_path_from, char *config_file_path_to, unsigned char include_config_data)
{
	//check for path validity
	char *ext = strrchr(config_file_path_from, '.');
	if (!ext || strcmp(ext, ".conf")) {
		printf("[CONFIG] Invalid config path: %s\n", config_file_path_from);
		return 1;
	}
	struct config_info *config_data = NULL;
	unsigned char       config_nr   = 0;
	if (include_config_data) {
		_fill_config_data(mib_data, &config_data, &config_nr);
	}

	//read the original config file for global setting
	FILE *fp = fopen(config_file_path_from, "r");
	if (fp == NULL) {
		printf("Error opening config file!\n");
		return 1;
	}

	char ** lines = NULL;
	size_t  len   = 0;
	ssize_t read;
	int     line_nr = 0;
	int     i       = 0;
	lines           = (char **)malloc(1 * sizeof(char *));
	lines[i]        = NULL;
	while ((read = getline(&lines[i], &len, fp)) != -1) {
		if ('\n' == lines[i][0]) {
			continue;
		}

		if ('[' == lines[i][0]) {
			if (0 == strncmp(lines[i], "[global]", 8)) {
				i        = 1;
				lines    = (char **)realloc(lines, (i + 1) * sizeof(char *));
				lines[i] = NULL;
				continue;
			} else {
				break;
			}
		}

		if (0 != i) {
			i++;
			lines    = (char **)realloc(lines, (i + 1) * sizeof(char *));
			lines[i] = NULL;
		}
	}

	line_nr = i;
	fclose(fp);
	//write info into the new config file
	fp = fopen(config_file_path_to, "w");
	for (i = 0; i < line_nr; i++) {
		fprintf(fp, "%s", lines[i]);
		free(lines[i]);
	}
	free(lines);

	fprintf(fp, "%s", "device_name = ");
	fprintf(fp, "%s\n", mib_data->device_name_buffer);
	////////////////////////////////////////////////////////////////////////////////
	if (config_data) {
		fprintf(fp, "[2.4g_config_data]\n");
		unsigned char  config_number = 0;
		char **        ssids         = (char **)malloc(1 * sizeof(char *));
		char **        network_keys  = (char **)malloc(1 * sizeof(char *));
		unsigned char *network_types = (unsigned char *)malloc(1 * sizeof(unsigned char));

		for (i = 0; i < config_nr; i++) {
			if (MAP_CONFIG_2G == config_data[i].config_type) {
				config_number++;
				ssids                            = (char **)realloc(ssids, (config_number) * sizeof(char *));
				network_keys                     = (char **)realloc(network_keys, (config_number) * sizeof(char *));
				network_types                    = (unsigned char *)realloc(network_types, (config_number) * sizeof(unsigned char));
				ssids[config_number - 1]         = config_data[i].ssid;
				network_keys[config_number - 1]  = config_data[i].network_key;
				network_types[config_number - 1] = config_data[i].network_type;
			}
		}

		fprintf(fp, "number = %d\n", config_number);
		fprintf(fp, "ssid = ");
		_writeToConfig(fp, config_number, ssids);

		fprintf(fp, "network_key = ");
		_writeToConfig(fp, config_number, network_keys);

		fprintf(fp, "network_type = ");
		_writeToConfig_dec(fp, config_number, network_types);

		free(ssids);
		free(network_keys);
		free(network_types);

		//vendor data test
		//fprintf(fp, "[vendor_data_2.4g]\n");
		//fprintf(fp, "vendor_data_nr = %d\n", 1);
		//fprintf(fp, "vendor_payload = %s\n", "2g TX restrict");
		//fprintf(fp, "vendor_oui = %s\n", "1c2d3e");

		fprintf(fp, "[5g_config_data]\n");
		config_number = 0;
		ssids         = (char **)malloc(1 * sizeof(char *));
		network_keys  = (char **)malloc(1 * sizeof(char *));
		network_types = (unsigned char *)malloc(1 * sizeof(unsigned char));

		for (i = 0; i < config_nr; i++) {
			if (MAP_CONFIG_5G == config_data[i].config_type) {
				config_number++;
				ssids                            = (char **)realloc(ssids, (config_number) * sizeof(char *));
				network_keys                     = (char **)realloc(network_keys, (config_number) * sizeof(char *));
				network_types                    = (unsigned char *)realloc(network_types, (config_number) * sizeof(unsigned char));
				ssids[config_number - 1]         = config_data[i].ssid;
				network_keys[config_number - 1]  = config_data[i].network_key;
				network_types[config_number - 1] = config_data[i].network_type;
			}
		}

		fprintf(fp, "number = %d\n", config_number);

		fprintf(fp, "ssid = ");
		_writeToConfig(fp, config_number, ssids);

		fprintf(fp, "network_key = ");
		_writeToConfig(fp, config_number, network_keys);

		fprintf(fp, "network_type = ");
		_writeToConfig_dec(fp, config_number, network_types);

		free(ssids);
		free(network_keys);
		free(network_types);
		free(config_data);

		
		//vendor data test
		//fprintf(fp, "[vendor_data_5g]\n");
		//fprintf(fp, "vendor_data_nr = %d\n", 1);
		//fprintf(fp, "vendor_payload = %s\n", "5g TX restrict");
		//fprintf(fp, "vendor_oui = %s\n", "1c2d3e");
	}
	fclose(fp);
	return 0;
}

void _write_mib_data(struct mib_info *mib_data, char *file_path)
{
	//check for path validity
	char *ext = strrchr(file_path, '.');
	if (!ext || strcmp(ext, ".conf")) {
		printf("[CONFIG] Invalid config path: %s\n", file_path);
		return 1;
	}

	FILE *fp = fopen(file_path, "w");

	fprintf(fp, "[global]\n");

	fprintf(fp, "%s", "configured_band = ");
	fprintf(fp, "%d\n", mib_data->map_configured_band);

	fprintf(fp, "%s", "hw_reg_domain = ");
	fprintf(fp, "%d\n", mib_data->reg_domain);

	int i = 0, j = 0;
	for (i = 0; i < mib_data->radio_nr; i++) {
		if (MAP_CONFIG_2G == mib_data->radio_data[i].radio_type) {
			fprintf(fp, "[mib_info_2.4g]\n");
		} else if (MAP_CONFIG_5G == mib_data->radio_data[i].radio_type) {
			fprintf(fp, "[mib_info_5g]\n");
		} else {
			continue;
		}

		fprintf(fp, "channel = %d\n", mib_data->radio_data[i].radio_channel);
		fprintf(fp, "channel_bandwidth = %d\n", mib_data->radio_data[i].radio_channel_bonding);
		fprintf(fp, "repeater_ssid = %s\n", mib_data->radio_data[i].repeater_ssid);
		fprintf(fp, "bss_number = %d\n", mib_data->radio_data[i].bss_nr);

		char **        ssids         = (char **)malloc((mib_data->radio_data[i].bss_nr) * sizeof(char *));
		char **        network_keys  = (char **)malloc((mib_data->radio_data[i].bss_nr) * sizeof(char *));
		unsigned char *is_enableds   = (unsigned char *)malloc((mib_data->radio_data[i].bss_nr) * sizeof(unsigned char));
		unsigned char *encrypt_types = (unsigned char *)malloc((mib_data->radio_data[i].bss_nr) * sizeof(unsigned char));

		for (j = 0; j < mib_data->radio_data[i].bss_nr; j++) {
			ssids[j]         = mib_data->radio_data[i].bss_data[j].ssid;
			network_keys[j]  = mib_data->radio_data[i].bss_data[j].network_key;
			is_enableds[j]   = mib_data->radio_data[i].bss_data[j].is_enabled;
			encrypt_types[j] = mib_data->radio_data[i].bss_data[j].encrypt_type;
		}
		fprintf(fp, "ssid = ");
		_writeToConfig(fp, mib_data->radio_data[i].bss_nr, ssids);
		fprintf(fp, "network_key = ");
		_writeToConfig(fp, mib_data->radio_data[i].bss_nr, network_keys);
		fprintf(fp, "is_enabled = ");
		_writeToConfig_dec(fp, mib_data->radio_data[i].bss_nr, is_enableds);
		fprintf(fp, "encrypt_type = ");
		_writeToConfig_dec(fp, mib_data->radio_data[i].bss_nr, encrypt_types);

		free(ssids);
		free(network_keys);
		free(is_enableds);
		free(encrypt_types);
	}

	fclose(fp);
	return 0;
}

void _free_mib_data(struct mib_info *mib_data)
{
	int i = 0;
	for (i = 0; i < mib_data->radio_nr; i++) {
		free(mib_data->radio_data[i].bss_data);
	}
	free(mib_data->radio_data);
}

void multi_ap_app()
{
	if (find_pid_by_name("map_controller") > 0) {
		system("killall -9 map_controller >/dev/null 2>&1");
	}

	if (find_pid_by_name("map_agent") > 0) {
		system("killall -9 map_agent >/dev/null 2>&1");
	}

	if (find_pid_by_name("map_controller_test") > 0) {
		system("killall -9 map_controller_test >/dev/null 2>&1");
	}

	if (find_pid_by_name("map_agent_test") > 0) {
		system("killall -9 map_agent_test >/dev/null 2>&1");
	}

	int map_state = 0;

	//set default name for the map device if device_name is empty
	char map_device_name[30];
	apmib_get(MIB_MAP_DEVICE_NAME, (void *)map_device_name);

	apmib_get(MIB_MAP_CONTROLLER, (void *)&map_state);

	if (!map_state)
		return;

	struct mib_info mib_data;
	_read_mib_to_config(&mib_data);

	if (map_state) {
		_write_mib_data(&mib_data, "/var/multiap_mib.conf");
		if(1 == map_state)
		{
			int op_mode = 0;
			apmib_get(MIB_OP_MODE, (void *)&op_mode);
			if(WISP_MODE == op_mode) {
				system("iwpriv wlan0-vxd set_mib a4_enable=0");/*set controller vxd a4 disabled*/				
				system("iwpriv wlan1-vxd set_mib a4_enable=0");/*set controller vxd a4 disabled*/	
			}
		}
	}

	switch (map_state) {
	case 1: {
		if (!strcmp(map_device_name, "")) {
			char *default_name_controller = "EasyMesh_Controller";
			// set into mib
			if (!apmib_set(MIB_MAP_DEVICE_NAME, (void *)default_name_controller)) {
				printf("[Error] : Failed to set AP mib MIB_MAP_DEVICE_NAME\n");
				return 0;
			}
			apmib_update(CURRENT_SETTING);
		}
		_update_config(&mib_data, "/etc/multiap.conf", "/var/multiap.conf", 1);
		int status = system("map_controller -dvv > /dev/null");
		printf("Multi AP controller daemon is running with %d\n", status);
		break;
	}
	case 2: {
		if (!strcmp(map_device_name, "")) {
			char *default_name_agent = "EasyMesh_Agent";
			// set into mib
			if (!apmib_set(MIB_MAP_DEVICE_NAME, (void *)default_name_agent)) {
				printf("[Error] : Failed to set AP mib MIB_MAP_DEVICE_NAME\n");
				return 0;
			}
			apmib_update(CURRENT_SETTING);
		}
		_update_config(&mib_data, "/etc/multiap.conf", "/var/multiap.conf", 0);
		int status = system("map_agent -dvv > /dev/null");
		printf("Multi AP agent daemon is running with %d\n", status);
		break;
	}
	case 129: {
		if (!strcmp(map_device_name, "")) {
			char *default_name_agent = "EasyMesh_Test_Controller";
			// set into mib
			if (!apmib_set(MIB_MAP_DEVICE_NAME, (void *)default_name_agent)) {
				printf("[Error] : Failed to set AP mib MIB_MAP_DEVICE_NAME\n");
				return 0;
			}
			apmib_update(CURRENT_SETTING);
		}
		_update_config(&mib_data, "/etc/multiap.conf", "/var/multiap.conf", 1);
		int status = system("map_controller_test -dvv > /dev/null");
		printf("Multi AP controller logo test daemon is running with %d\n", status);
		break;
	}
	case 130: {
		if (!strcmp(map_device_name, "")) {
			char *default_name_agent = "EasyMesh_Test_Agent";
			// set into mib
			if (!apmib_set(MIB_MAP_DEVICE_NAME, (void *)default_name_agent)) {
				printf("[Error] : Failed to set AP mib MIB_MAP_DEVICE_NAME\n");
				return 0;
			}
			apmib_update(CURRENT_SETTING);
		}
		_update_config(&mib_data, "/etc/multiap.conf", "/var/multiap.conf", 0);
		int status = system("map_agent_test -dvv > /dev/null");
		printf("Multi AP agent logo test daemon is running with %d\n", status);
		break;
	}
	}

	_free_mib_data(&mib_data);
}
