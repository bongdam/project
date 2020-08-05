#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bcmnvram.h>
#include <libytool.h>

/*--------------------------------------------------------------------------*/
#define DAVO_WME_RULE_SIZE_802_1P   8
#define DAVO_WME_RULE_SIZE_DSCP     64

#define READ_WME_MODE		0
#define READ_WME_1P			1
#define READ_WME_DSCP		2

#define WME_PROC_MODE   1
#define WME_PROC_8021P  2
#define WME_PROC_DSCP   3

enum {
	DAVO_WME_OVERRIDE_DISABLE,
	DAVO_WME_OVERRIDE_802_1P,
	DAVO_WME_OVERRIDE_DSCP,
};

/*--------------------------------------------------------------------------*/
/*
 * These tables should be same in linux driver source (dv_wlan.c)
 *
 */
const unsigned char def_rule_802_1p[DAVO_WME_RULE_SIZE_802_1P] = {
	0, 1, 2, 3, 4, 5, 6, 7
};
//wmm mapping value changed
const unsigned char def_rule_dscp[DAVO_WME_RULE_SIZE_DSCP] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 4, 4, 4,
	6, 6, 6, 6, 6, 6, 6, 6,
	6, 6, 6, 6, 6, 6, 6, 6,
	7, 7, 7, 7, 7, 7, 7, 7
};

static int g_davo_wme_override[2];
static unsigned char rule_802_1p[DAVO_WME_RULE_SIZE_802_1P];
static unsigned char rule_dscp[DAVO_WME_RULE_SIZE_DSCP];

/*--------------------------------------------------------------------------*/
/*
 *  Read current running configuration from system
 */
static void *read_wme_setting_from_file(int wl_idx, int wme_mode, int v6)
{
	FILE *fp;
	char *ptr, buf[80];
	int a[DAVO_WME_RULE_SIZE_DSCP];
	int n, i;
	char dv_wlan[80];
	void *pv = NULL;

	if ( wme_mode == READ_WME_MODE) {
		/* read mode    */
		pv = &g_davo_wme_override[0];
		dv_wlan[0]=0;
		sprintf(&dv_wlan[0], "/proc/dv_wlan%s/wme_mode", (wl_idx==0)?"0":"1");
		if ((fp=fopen(dv_wlan, "r")) != NULL) {
			if (fgets(buf, sizeof(buf), fp) != NULL) {
				g_davo_wme_override[wl_idx] = atoi(buf);
			}
			fclose(fp);
		}

	}
	else if ( wme_mode == READ_WME_1P) {
		/* read 802.1p map    */
		pv = &rule_802_1p[0];
		dv_wlan[0]=0;
		memset(&rule_802_1p[0], 0, sizeof(rule_802_1p));
		sprintf(&dv_wlan[0], "/proc/dv_wlan%s/wme_1p", (wl_idx==0)?"0":"1");
		if ((fp=fopen(dv_wlan, "r")) != NULL) {
			if (fgets(buf, sizeof(buf), fp) != NULL && (ptr=strchr(buf, ':')) != NULL) {
				if ( (n = sscanf(ptr+1, "%d %d %d %d %d %d %d %d",
						&a[0],&a[1],&a[2],&a[3],&a[4],&a[5],&a[6],&a[7])) == DAVO_WME_RULE_SIZE_802_1P) {
					for ( i = 0; i < 8 ; i++)
						rule_802_1p[i] = (unsigned char)a[i];
				}
			}
			fclose(fp);
		}
	}
	else {
		/* read DSCP map    */
		pv = &rule_dscp[0];
		n = i = 0;
		dv_wlan[0]=0;
		memset(&rule_dscp[0], 0, sizeof(rule_dscp));
		sprintf(&dv_wlan[0], "/proc/dv_wlan%s/%s", (wl_idx==0)?"0":"1", (v6)? "wme_dscp6": "wme_dscp" );
		if ((fp=fopen(dv_wlan, "r")) != NULL) {
			while (fgets(buf, sizeof(buf), fp) != NULL && (ptr=strchr(buf, ':')) != NULL) {
				n += sscanf(ptr+1, "%d %d %d %d %d %d %d %d",
						&a[i+0],&a[i+1],&a[i+2],&a[i+3],&a[i+4],&a[i+5],&a[i+6],&a[i+7]);
				i += 8;
			}
			if ( n==DAVO_WME_RULE_SIZE_DSCP ) {
				for ( i =0; i < DAVO_WME_RULE_SIZE_DSCP; i++)
					rule_dscp[i] = (unsigned char)a[i];
			}

			fclose(fp);
		}
	}

	return pv;
}

static void write_wme_mode_to_file(int wl_idx, int wmm_mode)
{
	char file_path[64];

	sprintf(file_path, "/proc/dv_wlan%d/wme_mode", wl_idx);

	yfecho(file_path, O_WRONLY, 0644, "%d\n", wmm_mode);
}

static void write_wme_802_1p_map_to_file(int wl_idx, const unsigned char *config_1p)
{
	char file_path[64];

	sprintf(file_path, "/proc/dv_wlan%d/wme_1p", wl_idx);

	yfecho(file_path, O_WRONLY, 0644, "0 %d %d %d %d %d %d %d %d\n",
			config_1p[0], config_1p[1], config_1p[2], config_1p[3],
			config_1p[4], config_1p[5], config_1p[6], config_1p[7]);
}

static void write_wme_dscp_map_to_file(int wl_idx, int index, const unsigned char *config_dscp, int v6)
{
	char file_path[64];

	sprintf(file_path, "/proc/dv_wlan%d/%s", wl_idx, (v6)? "wme_dscp6":"wme_dscp");

	yfecho(file_path, O_WRONLY, 0644, "%d %d %d %d %d %d %d %d %d\n",
			index,
			config_dscp[0], config_dscp[1], config_dscp[2], config_dscp[3],
			config_dscp[4], config_dscp[5], config_dscp[6], config_dscp[7]);
}

/*--------------------------------------------------------------------------*/
/*
 *  Get configuration from flash mib
 */
static int get_wlan_wme_mode(int wl_idx, int *mode)
{
	char nv_name[32], *pstr=NULL;
	int vMode;

	sprintf(nv_name, "x_wlan%s_wme_mode", wl_idx==0?"0":"1");
	pstr = nvram_get(nv_name);

	if (pstr) {
		vMode = atoi(pstr);
		if ( vMode >=DAVO_WME_OVERRIDE_DISABLE && vMode <= DAVO_WME_OVERRIDE_DSCP) {
			*mode = vMode;
			return (1);
		}
	}
	return (0);
}

static int get_wlan_wme_802_1p_map(int wl_idx, unsigned char *config_1p)
{
	char nv_name[32], *pstr=NULL;
	int int_array[8];
	int ret=0;
	int i;

	if ( !config_1p )
		return 0;

	sprintf(nv_name, "WLAN%s_WME_1P", wl_idx==0?"0":"1");
	pstr = nvram_get(nv_name);

	if (pstr) {
		if ( (ret = sscanf(pstr, "%d_%d_%d_%d_%d_%d_%d_%d",
				&int_array[0],&int_array[1],&int_array[2],&int_array[3],
				&int_array[4],&int_array[5],&int_array[6],&int_array[7])) == 8) {
			for ( i=0; i < 8; i++)
				config_1p[i] = (unsigned char)int_array[i];
		}
	}

	return ret;
}

static int get_wlan_wme_dscp_map(int wl_idx, int index, unsigned char m[8], int v6)
{
	char nv_name[32], *pstr=NULL;
	int i, ret=0, a[8];
	int tbl_idx;

	if ((index%8) != 0)
		return (0);

	tbl_idx = index >> 3;

	if (v6) {
		sprintf(nv_name, "WLAN%s_WME_DSCP6_%02d", wl_idx==0?"0":"1", index);
	} else {
		sprintf(nv_name, "WLAN%s_WME_DSCP%02d", wl_idx==0?"0":"1", index);
	}

	pstr = nvram_get(nv_name);

	if (pstr) {
		if ( (ret = sscanf(pstr, "%d_%d_%d_%d_%d_%d_%d_%d",
			&a[0],&a[1],&a[2],&a[3],&a[4],&a[5],&a[6],&a[7])) == 8 ) {
			for (i=0; i<8; i++)
				m[i] = a[i];
		}
	}
	return (ret==8);
}

/*--------------------------------------------------------------------------*/
static void apply_wlan_wme_config_to_system(int v6)
{
	unsigned char a[8];
	int i, mode;
	int wl_idx;
	int dscp_idx=0;
	unsigned char *p;
	int *pi;
	int s;
	int apply_type = (v6)? 2: 1;
	/* DSCP map    */
	for (wl_idx=0; wl_idx < 2; wl_idx++) {
		/* mode    */
		pi = (int *)read_wme_setting_from_file(wl_idx, READ_WME_MODE, 0);
		if (get_wlan_wme_mode(wl_idx, &mode) && mode != pi[wl_idx]) {
			pi[wl_idx] = mode;
			write_wme_mode_to_file(wl_idx, mode);
		}

		/* 802.1p map    */
		p = (unsigned char *)read_wme_setting_from_file(wl_idx, READ_WME_1P, 0);
		memset(&a[0], 0, sizeof(a));
		if (get_wlan_wme_802_1p_map(wl_idx, a) && memcmp(a, p, 8)!=0) {
			memcpy(&p[0], &a[0], 8);
			write_wme_802_1p_map_to_file(wl_idx, a);
		}
		/* wmm mapping value */
		for ( s =0; s < apply_type; s++ ) {
			p = (unsigned char *)read_wme_setting_from_file(wl_idx, READ_WME_DSCP, s);
	 		for (i = 0; i < 8 ; i++) {
				dscp_idx = i << 3;
				if (get_wlan_wme_dscp_map(wl_idx, dscp_idx, a, s) && memcmp(a, &p[dscp_idx], 8)!=0) {
					memcpy(&p[dscp_idx], &a[0], 8);
					write_wme_dscp_map_to_file(wl_idx, dscp_idx, a, s);
				}
			}
		}
	}
}

static void restoredefault_wlan_wme_dscp(int v6)
{
	int i;
	int wl_idx;
	int apply_type = (v6)? 2: 1;
	int s;
	char nv_name[32], nv_value[64];

	for( wl_idx = 0; wl_idx < 2; wl_idx++) {
		g_davo_wme_override[wl_idx] = DAVO_WME_OVERRIDE_DSCP;

		/* mode    */
		sprintf(nv_name, "x_wlan%s_wme_mode", wl_idx==0?"0":"1");
		sprintf(nv_value, "%d", DAVO_WME_OVERRIDE_DSCP);
		nvram_set(nv_name, nv_value);
		write_wme_mode_to_file(wl_idx, DAVO_WME_OVERRIDE_DSCP);

		/* 802.1p map    */
		sprintf(nv_name, "WLAN%s_WME_1P", wl_idx==0?"0":"1");
		nvram_set(nv_name, "");
		write_wme_802_1p_map_to_file(wl_idx, def_rule_802_1p);

		/* DSCP map    */
		for ( s = 0; s < apply_type; s++ ) {
			for (i=0; i<DAVO_WME_RULE_SIZE_DSCP; i+=8) {
				sprintf(nv_name, "WLAN%s_WME_%s_%02d", wl_idx==0?"0":"1", s==0?"DSCP":"DSCP6", i);
				nvram_set(nv_name, "");
				write_wme_dscp_map_to_file(wl_idx, i, &def_rule_dscp[i], s);
			}
		}
	}
}

/*--------------------------------------------------------------------------*/
/*
 *  Set configuration from flash mib
 */
static int change_wlan_wme_mode(int wl_idx, int wmm_mode)
{
	int *p_read;
	char nv_name[32], nv_value[64];

	if  ( !(p_read=(int *)read_wme_setting_from_file(wl_idx, READ_WME_MODE, 0)) )
		return -1;

	if (wmm_mode >=DAVO_WME_OVERRIDE_DISABLE && wmm_mode <= DAVO_WME_OVERRIDE_DSCP) {
		if (wmm_mode != p_read[wl_idx]) {
			p_read[wl_idx] = wmm_mode;
			sprintf(nv_name, "x_wlan%s_wme_mode", wl_idx==0?"0":"1");
			sprintf(nv_value, "%d", wmm_mode);
			nvram_set(nv_name, nv_value);
			write_wme_mode_to_file(wl_idx, wmm_mode);
		}
		return 0;
	}
	return -1;
}

static int change_wlan_wme_802_1p(int wl_idx, char *file)
{
	int index, pri;
	char *p, *q, value[60];
	unsigned char  config_1p[8];
	unsigned char *p_read;
	char buf[80];
	FILE *fp;
	char nv_name[32];

	if  ( !(p_read=(unsigned char *)read_wme_setting_from_file(wl_idx, READ_WME_1P, 0)) )
		return -1;

	memset(&config_1p[0], 0, sizeof(config_1p));
	if ( (fp = fopen(file, "r")) ) {
		while( fgets(buf, sizeof(buf), fp)) {
			q = &buf[0];
			if ( (p = strsep(&q, ":")) && q ) {
				index = atoi(p);
				pri = atoi(q);
				if ( index >=0 && index < DAVO_WME_RULE_SIZE_802_1P)
					config_1p[index] = pri;
			}
		}
		fclose(fp);
	}

	if (memcmp(&config_1p[0], &p_read[0], DAVO_WME_RULE_SIZE_802_1P) != 0) {
		sprintf(nv_name, "WLAN%s_WME_1P", wl_idx==0?"0":"1");
		if (memcmp(&config_1p[0], def_rule_802_1p, DAVO_WME_RULE_SIZE_802_1P)) {
			snprintf(value, sizeof(value), "%d_%d_%d_%d_%d_%d_%d_%d",
					config_1p[0], config_1p[1], config_1p[2], config_1p[3],
					config_1p[4], config_1p[5], config_1p[6], config_1p[7]);

			nvram_set(nv_name, value);
			write_wme_802_1p_map_to_file(wl_idx, &config_1p[0]);
		}
	}

	return (0);
}

static int change_wlan_wme_dscp(int wl_idx, char *file, int v6)
{
	int i, index, pri;
	char *p, *q, value[60], nv_name[20];
	unsigned char  config_dscp[DAVO_WME_RULE_SIZE_DSCP];
	int mib_idx;
	unsigned char *p_read;
	char buf[80];
	FILE *fp;

	if  ( !(p_read=(unsigned char *)read_wme_setting_from_file(wl_idx, READ_WME_DSCP, v6)) )
		return -1;

	memset(&config_dscp[0], 0, sizeof(config_dscp));
	if ( (fp = fopen(file, "r")) ) {
		while( fgets(buf, sizeof(buf), fp)) {
			q = &buf[0];
			if ( (p = strsep(&q, ":")) && q ) {
				index = atoi(p);
				pri = atoi(q);
				if ( index >=0 && index < DAVO_WME_RULE_SIZE_DSCP)
					config_dscp[index] = pri;
			}
		}
		fclose(fp);
		for (i=0, mib_idx=0; i<DAVO_WME_RULE_SIZE_DSCP; i+=8, mib_idx++) {
			if ( memcmp(&config_dscp[i], &p_read[i], 8) ) {
				if (v6)
					snprintf(nv_name, sizeof(nv_name), "WLAN%d_WME_DSCP6_%02d", wl_idx, i);
				else
					snprintf(nv_name, sizeof(nv_name), "WLAN%d_WME_DSCP%02d", wl_idx, i);
				sprintf(value, "%d_%d_%d_%d_%d_%d_%d_%d",
					config_dscp[i+0], config_dscp[i+1], config_dscp[i+2], config_dscp[i+3],
					config_dscp[i+4], config_dscp[i+5], config_dscp[i+6], config_dscp[i+7]);

				nvram_set(nv_name, value);
				write_wme_dscp_map_to_file(wl_idx, i, &config_dscp[i], v6);
			}
		}
	}

	return (0);
}

/*--------------------------------------------------------------------------*/
static void print_wlan_wme_config(void)
{
	int i, wl_idx;
	int *pi;
	unsigned char *p;
	int s;

	for( wl_idx =0; wl_idx < 2; wl_idx++) {
		pi = (int *)read_wme_setting_from_file(wl_idx, READ_WME_MODE, 0);
		printf("\n\n============================================================\n");
		printf("   802.11e WLAN_%d(%s) WMM priority mapping configuration\n", wl_idx, (wl_idx==0)? "5G":"2.4G");
		printf("------------------------------------------------------------\n");
		printf("Mode: ");
		if (pi[wl_idx] ==DAVO_WME_OVERRIDE_DISABLE) {
			printf("%d (802.11e (WMM) QoS mapping is disabled)\n", pi[wl_idx]);
		} else if (pi[wl_idx]==DAVO_WME_OVERRIDE_802_1P) {
			printf("%d: (802.11e (WMM) QoS mapping by 802.1p VLAN Tag priority)\n", pi[wl_idx]);
		} else if (pi[wl_idx]==DAVO_WME_OVERRIDE_DSCP) {
			printf("%d: (802.11e (WMM) QoS mapping by IP DSCP field)\n", pi[wl_idx]);
		} else {
			printf("%d: (unknown setting)\n", pi[wl_idx]);
		}

		p = (unsigned char *)read_wme_setting_from_file(wl_idx, READ_WME_1P, 0);
		printf("------------------------------------------------------------\n");
		printf("   Mapping rule: 802.1p VLAN PRI --> 802.11e WMM AC priority\n");
		printf("------------------------------------------------------------\n");
		printf("PRI[0 - 7]: %2d %2d %2d %2d %2d %2d %2d %2d\n",
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

		for ( s = 0; s < 2; s++ ) {
			p = (unsigned char *)read_wme_setting_from_file(wl_idx, READ_WME_DSCP, s);
			printf("----------------------------------------------------------------\n");
			printf("   *%s Mapping rule: IP DSCP value --> 802.11e WMM AC priority\n",
				(s)? "IPv6": "IPv4" );
			printf("----------------------------------------------------------------\n");
			for (i=0; i<DAVO_WME_RULE_SIZE_DSCP; i+=8) {
				printf("DSCP[%2d - %2d]: %2d %2d %2d %2d %2d %2d %2d %2d\n",
						i, i+7,
						p[i+0], p[i+1], p[i+2], p[i+3], p[i+4], p[i+5], p[i+6], p[i+7]);
			}
			printf("================================================================\n");
		}
		printf("================================================================\n");
	}

}

/*--------------------------------------------------------------------------*/
static void print_help(void)
{
	puts("Usage: \n"
		 "wmmmap -s\n"
		 "       	show\n"
		 "       -a\n"
		 "          apply\n"
		 "       -r\n"
		 "          default\n"
		 "       -p -i index(0=5g, 1=2g) -c config-file(format:\"[<802.1p-priority>:<802.11e-priority>...]\"))\n"
		 "          802.1p\n"
		 "       -d -i index(0=5g, 1=2g) -c config-file(format:\"[<DSCP-value>:<802.11e-priority>...]\") )\n"
		 "          dscp\n"
		 "       -m (0=disable-mapping, 1=mapping by 802.1p, 2=mapping by DSCP) -i (0=5g, 1=2g) \n"
		 "          mode\n"
		 "       -6\n"
		 "          Ipv6 \n"
		 "       -h\n"
		 "          help\n");
}

#define WMM_8021P	1
#define WMM_DSCP	2
#define WMM_MASK 	3
int wmmmap_main(int argc, char *argv[])
{
	int opt;
	int dv_wlan_idx=-1;
	int wmm_mode = -1, mode = 0;
	char config_filepath[80];
	int wmm_apply = 0;
	int other_run = 0;
	int v6_setup = 0;

	int restore_default = 0;

	if ( argc == 1) {
		print_help();
		return 0;
	}

	config_filepath[0]=0;
	while ( (opt=getopt(argc, argv, "sarpdho6m:i:c:")) != -1 ) {
		switch (opt)
		{
			case 's': //show
				print_wlan_wme_config();
				return 0;
			case 'a': //apply
				wmm_apply = 1;
				break;
			case 'r': //default
				restore_default = 1;
				break;

			case 'p': //1p(need index)
				mode |= WMM_8021P;
				break;
			case 'd': //dscp(need index)
				mode |= WMM_DSCP;
				break;
			case 'm': //mode(need index)
				wmm_mode = strtoul(optarg, NULL, 10);
				break;
			case 'i': //wlan index 0:5g 1:2.4g
				dv_wlan_idx = strtoul(optarg, NULL, 10);
				break;
			case 'c': //config(filename)
				sprintf(config_filepath, "%s", optarg);
				break;
			case 'o':
				other_run = 1;
				break;
			case '6':
				v6_setup = 1;
				break;
			case 'h': //help
			default: //unknown
				print_help();
				return 0;
		}
	}

	if (restore_default) {
		restoredefault_wlan_wme_dscp(v6_setup);
		return 0;
	}

	if ( (mode=(mode & WMM_MASK)) ) {
		if ( dv_wlan_idx < 0 )
			return -1;

		if ( config_filepath[0]==0 || access(config_filepath, F_OK) )
			return -1;

		if ( mode == WMM_8021P)
			change_wlan_wme_802_1p(dv_wlan_idx, config_filepath);
		else if ( mode == WMM_DSCP)
			change_wlan_wme_dscp(dv_wlan_idx, config_filepath, v6_setup);
	}

	if (wmm_mode >= 0)
		change_wlan_wme_mode(dv_wlan_idx, wmm_mode);

	if (wmm_apply) {
		apply_wlan_wme_config_to_system(v6_setup);
	}

	if ( config_filepath[0]!=0)
		unlink(config_filepath);

	if (!other_run) {
		nvram_commit();
	}

	return 0;
}

