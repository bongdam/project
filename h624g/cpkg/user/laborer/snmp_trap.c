#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <bcmnvram.h>
#include <libytool.h>
#include <syslog.h>
#include <linux/wireless.h>
#include "instrument.h"
#include "laborer.h"

#define ASIC_COL_NUM 8

#define RX_ASIC						0
#define TX_ASIC						1

#define OCTETS_ASIC 				1
#define UNICAST_ASIC 				2
#define MULTICAST_ASIC 				3
#define BROADCAST_ASIC				4
#define JAB_ERROR_DISCARDS_ASIC		5
#define FRAG_ERROR_DEFERED_ASIC		6
#define FCS_PAUSE_ASIC				7

long sched_trap_timer(unsigned int sec);
long trap_timer_id;
long trap_wlss_timer_id;
long trap_wiress_timer_id;

static unsigned long crc_wanalm;
static unsigned long over_wancrc(void);

#define WLAN_MBSSID_NUM				4
#define SIOCGIWRTLSTANUM			0x8B31

struct wlan_config_t {
	unsigned int root_mask[2];
	unsigned int va_mask[2];
};

static struct wlan_config_t wlconf;

#define RX_HIST "/proc/rx_hist"
#define TX_HIST "/proc/tx_hist"

unsigned long long get_wirelesstraffic()
{
	unsigned int tx_low, tx_high, find;
	unsigned long long total = 0;
	char fileName[128];
	char buf[128], tmp[64];
	FILE *fp;
	int w_idx, va_idx;

	for(w_idx = 0; w_idx < 2; w_idx++) {
		for(va_idx = 0; va_idx <= 4; va_idx++) {
			find = tx_low = tx_high = 0;

			if (va_idx == 0)
				snprintf(fileName, sizeof(fileName), "/proc/wlan%d/stats", w_idx);
			else
				snprintf(fileName, sizeof(fileName), "/proc/wlan%d-va%d/stats", w_idx, va_idx - 1);

			fp = fopen(fileName, "r");
			if (fp == NULL)
				return 0;

			while (fgets(buf, sizeof(buf), fp) != NULL) {
				if (strstr(buf, "tx_only_data_bytes:")) {
					if (sscanf(buf, "%s %u", tmp, &tx_low) == 2)
						find++;
				}

				if (strstr(buf, "tx_only_data_bytes_high:")) {
					if (sscanf(buf, "%s %u", tmp, &tx_high) == 2)
						find++;
				}

				if (find >= 2)
					break;
			}
			fclose(fp);
			total += tx_low + (tx_high * 0x400000);
		}
	}
	return total;
}

unsigned long traffic_info[5];
static unsigned long cal_traffic(int port, const char *file, int sec)
{
	int i;
	FILE *fp;
	char buf[80];
	unsigned long total = 0;

	if ( (fp=fopen(file, "r")) ) {
		i = 0;
		while( fgets(buf, sizeof(buf), fp) ) {
			sscanf(buf, "%lu %lu %lu %lu %lu\n",
						&traffic_info[0],&traffic_info[1],&traffic_info[2],
						&traffic_info[3],&traffic_info[4]);
			total += traffic_info[port];

			if ( ++i >= sec )
				break;
		}
		fclose(fp);
	}
	return total;
}

static int is_overlimit(int port, int dir, unsigned long *total, int lmt_band_byte, int sec)
{
	unsigned long tbsec = 0;

	*total=cal_traffic(port, (dir)?TX_HIST: RX_HIST, sec);
	tbsec = (*total/sec);
	*total = tbsec;
	if ( tbsec >= lmt_band_byte )
		return 1;
	return 0;
}


static int getwlassoc_num( const char* wlintf, int *num )
{
	int skfd=0;
	unsigned short staNum;
	struct iwreq wrq;

	if ( (skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return 0;

	strncpy(&wrq.ifr_name, wlintf, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&staNum;
	wrq.u.data.length = sizeof(staNum);

	if ( ioctl(skfd, SIOCGIWRTLSTANUM, &wrq) < 0 ) {
		close( skfd );
		return -1;
	}
	*num  = (int)staNum;
	close( skfd );

	return *num;
}

static char * express_unit(char *buf, unsigned long tbyte, int sec, int is_mbps)
{
	unsigned long kb = 0;
	unsigned long total = 0;

	total = (tbyte<<3);

	if ( sec )
		total = (total/sec);

	if ( is_mbps )		// convert to Mbps
		kb = (total >> 10);
	else				// convert to Kbps
		kb = total;

	buf[0] = 0;
	sprintf(&buf[0], "%lu.%lu", (kb>>10), (((kb%1024)*10)>>10));

	return buf;
}

static int get_wlsta_count(int band)
{
	int ii;
	char wl_intf[80];
	int val = 0, total_sta_n=0;

	if ( !wlconf.root_mask[band] )
		return 0;

	wl_intf[0]=0;
	sprintf(wl_intf, "wlan%d", band);
	getwlassoc_num(wl_intf, &total_sta_n);
	for (ii = 0; ii < WLAN_MBSSID_NUM; ii++) {
		if (!(wlconf.va_mask[band]& (1<<ii)) )
			continue;
		wl_intf[0]=0;
		val = 0;
		sprintf(wl_intf, "wlan%d-va%d", band, ii);
		total_sta_n += getwlassoc_num(wl_intf, &val);
	}
	return total_sta_n;
}

void monitor_wlss_trap(int type)
{
	int i;
	unsigned long total = 0, wl_bytes_diff = 0;
	unsigned long long wl_bytes_now = 0;
	static unsigned long long wl_bytes_old = 0;
	char buf[80], buf1[80], var[80];
	int connected_sta_n[2]={0};
	static int overing = 0;
	int lmt_band_byte, wl_lmt_band_count[2];
	int is_over;
	char trap_cmd[128];

	trap_cmd[0] = 0;
	nvram_get_r_def("x_snmp_wireslimit", buf, sizeof(buf), "80");//Mbps
	lmt_band_byte=strtoul(buf, NULL, 10);
	lmt_band_byte = (lmt_band_byte << 17);

	for ( i=0; i < 2; i++ ) {
		sprintf(var, "x_snmp_wl%dslimit", i);
		nvram_get_r_def(var, buf, sizeof(buf), "10");
		wl_lmt_band_count[i] = strtoul(buf, NULL, 10);
	}
	
	for ( i = 0; i < 2; i++)
		connected_sta_n[i] = get_wlsta_count(i);

	is_over = is_overlimit(4, 0, &total, lmt_band_byte, 60);
	wl_bytes_now = get_wirelesstraffic();
	wl_bytes_diff = wl_bytes_now - wl_bytes_old;
	wl_bytes_old = wl_bytes_now;

	if ( type == 1 ) {
		if ( is_over ) {
			overing++;
			syslog( ((overing==3)?LOG_INFO:LOG_DEBUG), "(Over %d)Down speed: %s Mbps(%lu Byte) CheckLimit(%s Mbps)\n",
						overing, express_unit(buf, total, 0, 1), total, express_unit(buf1, lmt_band_byte, 0, 1));
		}
		else {
			if (overing)
				overing--;
		}
		if ( overing == 3 ) {
			overing--;
			sprintf(&trap_cmd[0], "sh -c \"snmp -m 6 %d_%d %s_%s &\"", 
						(connected_sta_n[0]+connected_sta_n[1]), 
						(wl_lmt_band_count[0]+wl_lmt_band_count[1]),
						express_unit(buf, total, 0, 1), express_unit(buf1, wl_bytes_diff, 60, 0) );
			yexecl(NULL, trap_cmd);
		}

#if 0
		if ( !crc_wanalm && (crc_wanalm=over_wancrc()) ) {
			yexecl(NULL, "sh -c \"snmp -m 4 %lu &\"", crc_wanalm);
		}
#endif
	} else {
		for ( i = 0; i < 2; i++) {
			if ( connected_sta_n[i] >= wl_lmt_band_count[i] ) {
				sprintf(&trap_cmd[0], "sh -c \"snmp -m 6 %d_%d %s_%s &\"", 
							connected_sta_n[i],wl_lmt_band_count[i],express_unit(buf, total, 0, 1), express_unit(buf1, wl_bytes_diff, 60, 0) );
				syslog(LOG_INFO, "Wlan session Trap %s(%d/%d).\n", 
							(i==1)?"2.4G":"5G", connected_sta_n[i], wl_lmt_band_count[i]);
				yexecl(NULL, trap_cmd);
			}
		}
	}
}

static long sched_send_trap(void)
{
	if (nvram_get_int("x_SNMP_TRAP_ENABLE", 1))
		return sched_trap_timer(nvram_get_int("x_SNMP_TRAP_PERIOD", 10800));
	return 0;
}

static int send_trap_callback(long id, unsigned long arg)
{
	if ( id == trap_timer_id )
		yexecl(NULL, "sh -c \"snmp -m 1 &\"");

	if ( id == trap_wlss_timer_id ) {
		monitor_wlss_trap(0);
		return 1;
	}

	if ( id == trap_wiress_timer_id) {
		monitor_wlss_trap(1);
		return 1;
	}
	trap_timer_id = sched_send_trap();
	return 0;
}

long sched_trap_timer(unsigned int sec)
{
	struct timeval tv;
	tv.tv_sec = sec;
	tv.tv_usec = 0;
	return itimer_creat(0UL, send_trap_callback, &tv);
}

static void get_wl_status(void)
{
	int i, ii;
	char buf[80];

	for (i = 0; i < 2; i++) {
		wlconf.va_mask[i] = 0;
		sprintf(buf, "WLAN%d_WLAN_DISABLED", i);
		if ( nvram_match(buf, "1") )
			continue;
		wlconf.root_mask[i] = 1;
		for (ii = 0; ii < WLAN_MBSSID_NUM; ii++) {
			snprintf(buf, sizeof(buf), "WLAN%d_VAP%d_WLAN_DISABLED", i, ii);
			if ( nvram_match(buf, "1") )
				continue;

			wlconf.va_mask[i] |= (1 << ii);
		}
	}
}

static int parse_line(char *line, char *argv[], int argvLen, const char *delim)
{
	char *q, *p = line;
	int i, argc = 0;
	
	while ((q = strsep(&p, delim))) {
		ydespaces(q);
		if (*q && (argc < argvLen))
			argv[argc++] = q;
	}
	for (i = argc; i < argvLen; i++)
		argv[i] = NULL;
		
	return argc;
}


static char *get_asicinfo(int dir, int port, int type, char *data, int data_len)
{
	FILE *fp;
	char buf[256];
	char *argv[ASIC_COL_NUM];
	int i, argc;
	int find_dir = -1;
	
	if ( type < OCTETS_ASIC || type > FCS_PAUSE_ASIC )
		return NULL;
	
	data[0] = 0;
	if ( (fp=fopen("/proc/asicCounter", "r")) ) {
		while( fgets(buf, sizeof(buf), fp)) {
			if ( (argc = parse_line(buf, argv, ASIC_COL_NUM, " :|\r\n\t")) ) {
				for ( i = 0; i < argc; i++ ) {
					if ( !strcmp(argv[i], "Transmit") )
						find_dir = TX_ASIC;
					else if ( !strcmp(argv[i], "Receive") )
						find_dir = RX_ASIC;
					
					if ( type > argc )
						break;
						
					if ( find_dir >= 0 ) {
						if ( dir == find_dir && (argv[0][0]-'0') == port ) {
							snprintf(data, data_len, "%s", argv[type]);
							break;
						}
					}
				}
			}
			buf[0] = 0;
			if ( data[0] )
				break;
		}
		fclose(fp);
	}
	return data;
}

static unsigned long over_wancrc(void)
{
	char buf[80];
	unsigned long sys_wancrc, base_wancrc = 0;
	
	if ( get_asicinfo(RX_ASIC, 4, FCS_PAUSE_ASIC, buf, sizeof(buf)) ) {
		sys_wancrc = strtoul(buf, NULL, 10);
	}
	base_wancrc = nvram_get_int("x_autoreboot_wancrc", 20);
	
	return ((sys_wancrc >= base_wancrc)? sys_wancrc: 0);
}

static void __attribute__ ((constructor)) register_trap_module(void)
{
	trap_timer_id = sched_send_trap();

	get_wl_status();
	//trap#6-1: check wifi session
	trap_wlss_timer_id = sched_trap_timer(nvram_get_int("x_SNMP_WLSESSION", 300));
	//trap#6-2: check wan traffic
	trap_wiress_timer_id = sched_trap_timer(nvram_get_int("x_SNMP_WIRESSION", 60));
}
