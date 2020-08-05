#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <8192cd.h>
#include <sys/syscall.h>
#endif
#include <sys/time.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <netdb.h>
#include <signal.h>
#include <sys/errno.h>
#include "linux_list.h"
#include "../include/dvflag.h"
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>

//#include "dvnvlib.h"
#include "defines.h"
#include "../../../users/auth/include/1x_ioctl.h"
#include "misc.h"
#include "snmp.h"
#include "agt_engine.h"
#include "skbb.h"
#include "snmp_main.h"
#include "skbb_api.h"
#include "snmp_trap.h"
#include "apmib.h"
#include <shutils.h>
#include <libytool.h>
#include <bcmnvram.h>

/* jihyun@davo160202 jcode#7 -*/
#define STA_EMPTY			0
#define STA_START			1
#define STA_STOP			2
#define STA_FAIL			4
#define STA_CONSTAT_MASK	0x7f
#define STA_HANDOVER_MASK	0x80
//#define STAMON_DBG		1
//+

#if !defined(__STATRAP_EVENT__)

#ifdef __DAVO__
#define MAX_WL_MONITOR 5	// 2.4G (main, sk_voip) | 5G (main, sk_voip, Handover SSID)
#else
#if defined(CONFIG_OEM_SKB)
#define MAX_WL_MONITOR 2
#else
#define MAX_WL_MONITOR 3
#endif
#endif				// __DAVO__

struct station_info {
	int inuse;
	int checked;
	int idle_expired;
	int wid;		// 0 SK_WIFI_5G, 1 SK_WIFI_2G, 2 SK_VoIP
	RTL_STA_INFO sta_info;
};

struct wl_monitor_t{
	unsigned int enable;
	unsigned char mac[6];
	unsigned char ssid[32];
	const char * wl_intf;
	const char * enable_nv;
	const char * ssid_nv;
};

#define WLSTA_POLL_PIDPATH 	"/var/run/snmp_wlsta_poll.pid"
#define WLSTA_INFO_SNMP  	"/var/tmp/wlsta_snmp"

static void close_stamon(void);
static void poll_stamon(void);
static void wl_monitor_init(void);

static int snmp_flag;
static struct station_info wl_allsta_info[MAX_WL_MONITOR * (MAX_SUPPLICANT_NUM + 1)];
static int make_wlall_status(RTL_STA_INFO *pStaInfo, int flag, int reason, int wid, char *msg, int msglen);

extern TDV_SNMP_CFG dvsnmp_cfg;

unsigned char *make_resp_tail(raw_snmp_info_t *pMsg, char *out_data, int *p_out_length);

static struct wl_monitor_t wl_monitor[6] = {
	{ 0, "", "", "wlan0", 		"WLAN0_WLAN_DISABLED", 		"WLAN0_SSID" },		//5G main
	{ 0, "", "", "wlan0-va0",	"WLAN0_VAP0_WLAN_DISABLED",	"WLAN0_VAP0_SSID" },//5G SK_VoIP
	{ 0, "", "", "wlan0-va3", 	"WLAN0_VAP3_WLAN_DISABLED", "WLAN0_VAP3_SSID" },//5G Handover
	{ 0, "", "", "wlan1",		"WLAN1_WLAN_DISABLED", 		"WLAN1_SSID" },		//2G main
	{ 0, "", "", "wlan1-va0",	"WLAN1_VAP0_WLAN_DISABLED", "WLAN1_VAP0_SSID" },//2G SK_VoIP
	{ 0, "", "", NULL, NULL, NULL}
};
#endif //__STATRAP_EVENT__
void *send_wlall_status_trap(char *msg, int msglen, char *trap_name);


static char *ether_ntoa(const unsigned char *addr, int delim)
{
	static char asc[18];
	int i, n;

	for (i = n = 0; i < (6 - 1); i++) {
		n += sprintf(&asc[n], "%02x", *addr++);
		if (delim)
			asc[n++] = delim;
	}
	sprintf(&asc[n], "%02x", *addr);
	return asc;
}

static int get_ntp(int f)
{
	if (f & DF_NTPSYNC) {
		return 1;
	}
	return 0;
}

static int enable_network(int f)
{
	long wan_ip = 0;

	if (f & DF_WANLINK) {
		return (get_wan_ip(&wan_ip, NULL));
	}
	return 0;
}


static char *bytes_meter(struct scaled_octet *p, char *buf, size_t len)
{
	const char rate_suffix[] = "\0\0K\0M\0G\0T";
	int i = dec_scaled_octet(p);

	snprintf(buf, len, "%lu.%u%sB",
		 (unsigned long)p->N, p->F / 100, &rate_suffix[i << 1]);
	return buf;
}

static int getIfHwAddr(char *devname, unsigned char *mac)
{
	int skfd;
	int ret = -1;
	struct ifreq ifr;
	int n;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return ret;

	strcpy(ifr.ifr_name, devname);
	if ( (n=ioctl(skfd, SIOCGIFHWADDR, &ifr)) < 0) {
		close(skfd);
		return -1;
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	ret = 0;

	close(skfd);

	return ret;
}

#if !defined(__STATRAP_EVENT__)

static int query_all_wlstainfo(RTL_STA_INFO ** ppStaInfo, const char *ifname)
{
	struct iwreq wrq;
	int wl_ioclt_fd;
	int ret;

	if ( (wl_ioclt_fd=socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	memset(ppStaInfo, 0, sizeof(RTL_STA_INFO) * (MAX_SUPPLICANT_NUM + 1));

	snprintf(wrq.ifr_name, IFNAMSIZ, "%s", ifname);
	wrq.u.data.pointer = (caddr_t) ppStaInfo;
	wrq.u.data.length = sizeof(RTL_STA_INFO) * (MAX_SUPPLICANT_NUM + 1);
	*((unsigned char *)wrq.u.data.pointer) = MAX_SUPPLICANT_NUM;

	if ( (ret = ((ioctl(wl_ioclt_fd, SIOCGIWRTLSTAINFO, &wrq) < 0) ? -1 : 0)) == 0)
		close(wl_ioclt_fd);

	return ret;
}

static int add_sta_info(RTL_STA_INFO *StaInfo, int id)
{
	int i;

	for (i = 0; i < MAX_WL_MONITOR * (MAX_SUPPLICANT_NUM + 1); i++) {
		if (wl_allsta_info[i].inuse == 0) {
			wl_allsta_info[i].inuse = 1;
			wl_allsta_info[i].checked = 1;
			wl_allsta_info[i].wid = id;
			memcpy((void *)&wl_allsta_info[i].sta_info, StaInfo, sizeof(RTL_STA_INFO));
			break;
		}
	}
	return 0;
}

static struct station_info *find_sta_info(unsigned char *addr, int id)
{
	int i;

	for (i = 0; i < (MAX_WL_MONITOR * (MAX_SUPPLICANT_NUM + 1)); i++) {
		if (wl_allsta_info[i].inuse) {
			if (!memcmp(wl_allsta_info[i].sta_info.addr, addr, 6) && wl_allsta_info[i].wid == id)
				return &wl_allsta_info[i];
		}
	}
	return NULL;
}

static void uncheck_sta_info(void)
{
	int i;

	for (i = 0; i < (MAX_WL_MONITOR * (MAX_SUPPLICANT_NUM + 1)); i++) {
		if (wl_allsta_info[i].inuse)
			wl_allsta_info[i].checked = 0;
	}
}

static void check_sta_info(void)
{
	int i;
	int reason;
	char msg[1024];
	int len;

	for (i = 0; i < MAX_WL_MONITOR * (MAX_SUPPLICANT_NUM + 1); i++) {
		if (wl_allsta_info[i].inuse && (wl_allsta_info[i].checked == 0)) {
			wl_allsta_info[i].inuse = 0;
			wl_allsta_info[i].checked = 0;
			/* send trap to snmp server */
			/* APNRTL-252 Change idle-timeout(4) to lost-carrier(2) because of usging idle-timeout in radius */
			reason = wl_allsta_info[i].idle_expired ? 2 : 1;
			if ((len = make_wlall_status(&wl_allsta_info[i].sta_info, STA_STOP, reason, wl_allsta_info[i].wid, msg, sizeof(msg))) > 0)
				send_wlall_status_trap(msg, len, WIFI_OFF_TRAP);
		}
	}
}

static int proc_sta_info(RTL_STA_INFO *pStaInfo, int id)
{
	int i;
	struct station_info *si;
	int reason;
	char msg[1024];
	int len;

	for (i = 0; i < MAX_SUPPLICANT_NUM + 1; i++) {
		if (pStaInfo[i].aid != 0) {
			si = find_sta_info(pStaInfo[i].addr, id);
			if (si == NULL) {
				if (pStaInfo[i].link_time < 6)
					continue;
				/* new one is joined */
				add_sta_info(&pStaInfo[i], id);

				/* send trap to snmp server */
				if ((len = make_wlall_status(&pStaInfo[i], STA_START, 0, id, msg, sizeof(msg))) > 0)
					send_wlall_status_trap(msg, len, WIFI_ON_TRAP);
			} else {
				if (pStaInfo[i].link_time < si->sta_info.link_time) {
					/* disconnected and reconnected in very short time */
					/* APNRTL-252 Change idle-timeout(4) to lost-carrier(2) because of usging idle-timeout in radius */
					reason = si->idle_expired ? 2 : 1;
					if ((len = make_wlall_status(&si->sta_info, STA_STOP, reason, id, msg, sizeof(msg))) > 0)
						send_wlall_status_trap(msg, len, WIFI_OFF_TRAP);

					if ((len = make_wlall_status(&pStaInfo[i], STA_START, reason, id, msg, sizeof(msg))) > 0)
						send_wlall_status_trap(msg, len, WIFI_ON_TRAP);
				}
				/* update sta_info */
				memcpy((void *)&si->sta_info, &pStaInfo[i], sizeof(RTL_STA_INFO));
				si->checked = 1;
				si->idle_expired = (pStaInfo[i].expired_time / 100 < 2) ? 1 : 0;
			}
		}
	}
	return 0;
}

static void wl_monitor_init(void)
{
	unsigned int i;

	i =0;
	while( wl_monitor[i].wl_intf ) {
		wl_monitor[i].enable = 0;
		if ( nvram_match(wl_monitor[i].enable_nv, "0") ) {
			wl_monitor[i].enable = 1;
			snprintf(&wl_monitor[i].ssid[0], sizeof(wl_monitor[i].ssid),
						"%s", getValue(wl_monitor[i].ssid_nv));
			if ( getIfHwAddr(wl_monitor[i].wl_intf, &wl_monitor[i].mac[0]) < 0 )
				memset(wl_monitor[i].mac, 0, sizeof(wl_monitor[i].mac));
		}
		i++;
	}
}

void monitor_wlsta_print(void)
{
	int i;
	FILE *fp;

	if ( !(fp = fopen("/var/tmp/wl_monitor", "w")) )
		return;

	for ( i =0; i < wl_monitor[i].wl_intf; i++ ) {
		fprintf(fp, "wl_monitor[%d].enable %d\n", i, wl_monitor[i].enable);
		fprintf(fp, "wl_monitor[%d].ssid %s\n", i, wl_monitor[i].ssid);
		fprintf(fp, "wl_monitor[%d].mac %02x:%02x:%02x:%02x:%02x:%02x\n",
					i, wl_monitor[i].mac[0], wl_monitor[i].mac[1], wl_monitor[i].mac[2],
					wl_monitor[i].mac[3], wl_monitor[i].mac[4], wl_monitor[i].mac[5]);
	}
	fclose(fp);
}



static void poll_stamon(void)
{
	int i;
	RTL_STA_INFO staInfo[MAX_WL_MONITOR][MAX_SUPPLICANT_NUM + 1];

	i = 0;
	uncheck_sta_info();
	for ( i =0; i < wl_monitor[i].wl_intf; i++ ) {
		if ( query_all_wlstainfo((RTL_STA_INFO **) staInfo[i], wl_monitor[i].wl_intf) == 0)
			proc_sta_info(staInfo[i], i);
	}
	check_sta_info();

}

static void close_stamon(void)
{
	int i;
	char msg[1024];
	int len;

	for (i = 0; i < MAX_WL_MONITOR * (MAX_SUPPLICANT_NUM + 1); i++) {
		if (wl_allsta_info[i].inuse) {
			wl_allsta_info[i].inuse = 0;
			wl_allsta_info[i].checked = 0;
			/* send trap to snmp server */
			if ((len = make_wlall_status(&wl_allsta_info[i].sta_info, STA_STOP, 7, wl_allsta_info[i].wid, msg, sizeof(msg))) > 0)
				send_wlall_status_trap(msg, len, WIFI_OFF_TRAP);
		}
	}
}

void record_stamon_info(void)
{
	int i;
	FILE *fp;
	RTL_STA_INFO *p;
	char id;

	if (!(fp = fopen(WLSTA_INFO_SNMP, "w")))
		return;
	for (i = 0; i < MAX_WL_MONITOR * (MAX_SUPPLICANT_NUM + 1); i++) {
		if (wl_allsta_info[i].inuse) {
			p = &wl_allsta_info[i].sta_info;
			id = wl_allsta_info[i].wid;
			fwrite(&p->link_time, sizeof(p->link_time), 1, fp);
			fwrite(&p->addr, sizeof(p->addr), 1, fp);
			fwrite(&p->rx_only_data_packets, sizeof(p->rx_only_data_packets), 1, fp);
			fwrite(&p->tx_only_data_packets, sizeof(p->tx_only_data_packets), 1, fp);
			fwrite(&p->rx_only_data_bytes, sizeof(p->rx_only_data_bytes), 1, fp);
			fwrite(&p->tx_only_data_bytes, sizeof(p->tx_only_data_bytes), 1, fp);
			fwrite(&id, sizeof(id), 1, fp);
		}
	}
	fclose(fp);
}

#define CLOSE_STA_SIZE	27
void clear_stamon_trap(void)
{
	int i, n, len;
	FILE *fp;
	RTL_STA_INFO *p;
	static struct station_info wlsta;
	struct stat file_stat;
	char id;
	char msg[1024];

	if (stat(WLSTA_INFO_SNMP, &file_stat) < 0)
		return;

	if (!(fp = fopen(WLSTA_INFO_SNMP, "r")))
		return;

	if ((file_stat.st_size % CLOSE_STA_SIZE) != 0) {
		fclose(fp);
		return;
	}

	for (i = 0; i < (n = (file_stat.st_size / CLOSE_STA_SIZE)); i++) {
		p = &wlsta.sta_info;
		fread(&p->link_time, sizeof(p->link_time), 1, fp);
		fread(&p->addr, sizeof(p->addr), 1, fp);
		fread(&p->rx_only_data_packets, sizeof(p->rx_only_data_packets), 1, fp);
		fread(&p->tx_only_data_packets, sizeof(p->tx_only_data_packets), 1, fp);
		fread(&p->rx_only_data_bytes, sizeof(p->rx_only_data_bytes), 1, fp);
		fread(&p->tx_only_data_bytes, sizeof(p->tx_only_data_bytes), 1, fp);
		fread(&id, sizeof(id), 1, fp);
		/* send trap to snmp server */
		if ((len = make_wlall_status(p, STA_STOP, 7, id, msg, sizeof(msg))) > 0)
			send_wlall_status_trap(msg, len, WIFI_OFF_TRAP);
	}
	fclose(fp);

	unlink(WLSTA_INFO_SNMP);
}

static int make_wlall_status(RTL_STA_INFO *psta, int flag, int reason, int wid, char *msg, int msglen)
{
	char buf[256];
	struct tm *tm;
	time_t tt;
	int n = 0;
	struct scaled_octet tx, rx;
	char quantity[2][32];
	char tmpMacstr[80];

	if (!msg)
		return 0;

	time(&tt);
	tm = localtime(&tt);

	sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
		tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
	msglen -= 1;
	sprintf(tmpMacstr, "%02x%02x%02x%02x%02x%02x",
				wl_monitor[wid].mac[0],wl_monitor[wid].mac[1],wl_monitor[wid].mac[2],
				wl_monitor[wid].mac[3],wl_monitor[wid].mac[4],wl_monitor[wid].mac[5]);

	if (flag == STA_START) {
		n = snprintf(&msg[n], msglen - n, "status=start\r\n");
		n += snprintf(&msg[n], msglen - n, "evt-time=%s\r\n", buf);
		//n += snprintf(&msg[n], msglen-n, "session-time=%lu\r\n", psta->link_time);
		n += snprintf(&msg[n], msglen - n, "session-time=0\r\n");
		n += snprintf(&msg[n], msglen - n, "ap-mac=%s\r\n", tmpMacstr);
		n += snprintf(&msg[n], msglen - n, "cpe-mac=%s\r\n", ether_ntoa(psta->addr, 0));
		n += snprintf(&msg[n], msglen - n, "ssid=%s\r\n", wl_monitor[wid].ssid);

		syslog(LOG_ALERT, "%s %s Connected %ddBm",
			   wl_monitor[wid].ssid, ether_ntoa(psta->addr, ':'), CONV_TO_RSSI(psta->rssi));
	} else {
		n = snprintf(&msg[n], msglen - n, "status=stop\r\n");
		n += snprintf(&msg[n], msglen - n, "evt-time=%s\r\n", buf);
		n += snprintf(&msg[n], msglen - n, "session-time=%lu\r\n", psta->link_time);
		n += snprintf(&msg[n], msglen - n, "ap-mac=%s\r\n", tmpMacstr);

		n += snprintf(&msg[n], msglen - n, "cpe-mac=%s\r\n", ether_ntoa(psta->addr, 0));
		n += snprintf(&msg[n], msglen - n, "ssid=%s\r\n", wl_monitor[wid].ssid);
		n += snprintf(&msg[n], msglen - n, "packet=%lu,%lu\r\n",
				  psta->rx_only_data_packets, psta->tx_only_data_packets);	/* APNRTL-238 In/Out */
		n += snprintf(&msg[n], msglen - n, "octet=%lu,%lu\r\n",
				  psta->rx_only_data_bytes, psta->tx_only_data_bytes);		/* To maintain unity, uses 'unsigned long' type  */
		//n += snprintf(&msg[n], msglen-n, "term-cause=%d\r\n", reason); // delete cause
		msg[n] = 0;

		tx.ull = psta->tx_bytes;
		rx.ull = psta->rx_bytes;
		syslog(LOG_ALERT, "%s %s Disconnected (%lu/%lu/%lu %lusec rate=0x%02x %s/%s %ddBm)",
			   wl_monitor[wid].ssid, ether_ntoa(psta->addr, ':'),
			   psta->tx_packets, psta->rx_packets, psta->tx_fail,
			   psta->link_time, psta->TxOperaRate,
			   bytes_meter(&tx, quantity[0], sizeof(quantity[0])),
			   bytes_meter(&rx, quantity[1], sizeof(quantity[0])),
			   CONV_TO_RSSI(psta->rssi));
	}

	return n;
}

static int write_ps_name(char *path)
{
	FILE *fp;

	if (!path)
		return -1;

	if ((fp = fopen(path, "w"))) {
		fprintf(fp, "%d", getpid());
		fclose(fp);
		return 1;
	}
	return 0;
}

static void child_exit_handle(int sig)
{
	if (enable_network(snmp_flag))
		close_stamon();
	else
		record_stamon_info();

	unlink(WLSTA_POLL_PIDPATH);

	exit(0);
}

/* @note: monitor all station for trap */
void monitor_wlsta_attend(void)
{
	struct timeval tv;
	struct sigaction sa;
	fd_set fdset;
	int link_fd;
	int flag, ret;

	if (write_ps_name(WLSTA_POLL_PIDPATH) < 1)
		exit(-1);

	if ((link_fd = open("/proc/dvflag", O_RDWR)) < 0)
		exit(-1);

	sa.sa_handler = child_exit_handle;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGTERM, &sa, 0);

	wl_monitor_init();

	flag = DF_WANLINK | DF_NTPSYNC;
	if (ioctl(link_fd, DVFLGIO_SETMASK, &flag))
		perror("ioctl");

	if (read(link_fd, (void *)&snmp_flag, sizeof(snmp_flag)) > 0) {
		snmp_flag = snmp_flag & (DF_WANLINK | DF_NTPSYNC);
	}
	while (1) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_ZERO(&fdset);
		FD_SET(link_fd, &fdset);

		ret = select(link_fd + 1, &fdset, NULL, NULL, &tv);
		if (ret == 0) {
			if ((enable_network(snmp_flag)) && get_ntp(snmp_flag)) {
				if (!access(WLSTA_INFO_SNMP, F_OK)) {
					sleep(1);
					clear_stamon_trap();
				}
				poll_stamon();
			}
		} else if ((ret < 0) && (errno == EINTR))
			continue;
		else {
			if (FD_ISSET(link_fd, &fdset)) {
				if (read(link_fd, (void *)&flag, sizeof(flag)))
					snmp_flag = flag & (DF_WANLINK | DF_NTPSYNC);
			}
		}
	}
	close(link_fd);
}
#else
/* jihyun@davo160202 jcode#7 -*/
/*
***********************************************************************************************************
***********************************************************************************************************
***********************************************************************************************************
*/
static int is_alive_wanline(void)
{
	int link_fd;
	int flag;
	int alive = 1;

	if ((link_fd = open("/proc/dvflag", O_RDWR)) < 0)
		return 0;

	flag = DF_WANLINK | DF_NTPSYNC;
	if (ioctl(link_fd, DVFLGIO_SETMASK, &flag)) {
		perror("ioctl");
		close(link_fd);
		return 0;
	}
	if (read(link_fd, (void *)&flag, sizeof(flag)) > 0)
		flag = flag & (DF_WANLINK | DF_NTPSYNC);

	if ((enable_network(flag)) && get_ntp(flag))
		alive = 1;
	close(link_fd);

	return alive;
}

#define MAX_STATION_NUM		64  // max support sta number
#define STA_INFO_FLAG_ASOC	0x04
const unsigned short VHT_MCS_DATA_RATE[3][2][30] =
{	{	{13, 26, 39, 52, 78, 104, 117, 130, 156, 156,
		 26, 52, 78, 104, 156, 208, 234, 260, 312, 312,
		 39, 78, 117, 156, 234, 312, 351, 390, 468, 520},					// Long GI, 20MHz

		{14, 29, 43, 58, 87, 116, 130, 144, 173, 173,
		 29, 58, 87, 116, 173, 231, 260, 289, 347, 347,
		 43, 86, 130, 173, 260, 347, 390, 433, 520, 578}			},		// Short GI, 20MHz

	{	{27, 54, 81, 108, 162, 216, 243, 270, 324, 360,
		 54, 108, 162, 216, 324, 432, 486, 540, 648, 720,
		 81, 162, 243, 342, 486, 648, 729, 810, 972, 1080}, 				// Long GI, 40MHz

		{30, 60, 90, 120, 180, 240, 270, 300,360, 400,
		 60, 120, 180, 240, 360, 480, 540, 600, 720, 800,
		 90, 180, 270, 360, 540, 720, 810, 900, 1080, 1200}			},		// Short GI, 40MHz

	{	{59, 117,  176, 234, 351, 468, 527, 585, 702, 780,
		 117, 234, 351, 468, 702, 936, 1053, 1170, 1404, 1560,
		 176, 351, 527, 702, 1053, 1408, 1408, 1745, 2106, 2340}, 			// Long GI, 80MHz

		{65, 130, 195, 260, 390, 520, 585, 650, 780, 867,
		 130, 260, 390, 520, 780, 1040, 1170, 1300, 1560, 1733,
		 195, 390, 585, 780, 1170, 1560, 1560, 1950, 2340, 2600}	}		// Short GI, 80MHz

};

WLAN_RATE_T rate_11n_table_20M_LONG[]={
	{MCS0, 	"6.5"},
	{MCS1, 	"13"},
	{MCS2, 	"19.5"},
	{MCS3, 	"26"},
	{MCS4, 	"39"},
	{MCS5, 	"52"},
	{MCS6, 	"58.5"},
	{MCS7, 	"65"},
	{MCS8, 	"13"},
	{MCS9, 	"26"},
	{MCS10, 	"39"},
	{MCS11, 	"52"},
	{MCS12, 	"78"},
	{MCS13, 	"104"},
	{MCS14, 	"117"},
	{MCS15, 	"130"},
	{0}
};
WLAN_RATE_T rate_11n_table_20M_SHORT[]={
	{MCS0, 	"7.2"},
	{MCS1, 	"14.4"},
	{MCS2, 	"21.7"},
	{MCS3, 	"28.9"},
	{MCS4, 	"43.3"},
	{MCS5, 	"57.8"},
	{MCS6, 	"65"},
	{MCS7, 	"72.2"},
	{MCS8, 	"14.4"},
	{MCS9, 	"28.9"},
	{MCS10, 	"43.3"},
	{MCS11, 	"57.8"},
	{MCS12, 	"86.7"},
	{MCS13, 	"115.6"},
	{MCS14, 	"130"},
	{MCS15, 	"144.5"},
	{0}
};
WLAN_RATE_T rate_11n_table_40M_LONG[]={
	{MCS0, 	"13.5"},
	{MCS1, 	"27"},
	{MCS2, 	"40.5"},
	{MCS3, 	"54"},
	{MCS4, 	"81"},
	{MCS5, 	"108"},
	{MCS6, 	"121.5"},
	{MCS7, 	"135"},
	{MCS8, 	"27"},
	{MCS9, 	"54"},
	{MCS10, 	"81"},
	{MCS11, 	"108"},
	{MCS12, 	"162"},
	{MCS13, 	"216"},
	{MCS14, 	"243"},
	{MCS15, 	"270"},
	{0}
};
WLAN_RATE_T rate_11n_table_40M_SHORT[]={
	{MCS0, 	"15"},
	{MCS1, 	"30"},
	{MCS2, 	"45"},
	{MCS3, 	"60"},
	{MCS4, 	"90"},
	{MCS5, 	"120"},
	{MCS6, 	"135"},
	{MCS7, 	"150"},
	{MCS8, 	"30"},
	{MCS9, 	"60"},
	{MCS10, 	"90"},
	{MCS11, 	"120"},
	{MCS12, 	"180"},
	{MCS13, 	"240"},
	{MCS14, 	"270"},
	{MCS15, 	"300"},
	{0}
};

void set_11ac_txrate(WLAN_STA_INFO_Tp pInfo, char* txrate, int len)
{
	char channelWidth = 0;//20M 0,40M 1,80M 2
	char shortGi = 0;
	char rate_idx = pInfo->TxOperaRate - 0xA0;

	if(!txrate)
		return;

	if(pInfo->ht_info & 0x4)
		channelWidth = 2;
	else if(pInfo->ht_info & 0x1)
		channelWidth = 1;
	else
		channelWidth = 0;
	if(pInfo->ht_info & 0x2)
		shortGi = 1;

	snprintf(txrate, len, "%d", VHT_MCS_DATA_RATE[channelWidth][shortGi][rate_idx]>>1);
}

static unsigned int get_cpe_link_rate(unsigned char *cpemac)
{
	int i, j, ret, band = 0;
	WLAN_STA_INFO_Tp pInfo;
	char *buff;
	char WLAN_IF[20];
	char txrate[20] = {0,};
	int rateid = 0;

	sleep(1);
	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STATION_NUM + 1));
	if (buff == 0) {
		printf("Allocate buffer failed!\n");
		return 0;
	}

	while (band < 2) {
		for (i = 0; i < MAX_SSID; i++) {
			if (i == 0)
				sprintf(WLAN_IF, "wlan%d", band);
			else
				sprintf(WLAN_IF, "wlan%d-va%d", band, i - 1);

			memset(buff, 0, sizeof(WLAN_STA_INFO_T) * (MAX_STATION_NUM + 1));
			if ((ret = getWlStaInfo(WLAN_IF, (WLAN_STA_INFO_Tp) buff)) < 0)
				continue;

			for (j = 1; j <= MAX_STATION_NUM; j++) {
				pInfo = (WLAN_STA_INFO_Tp)&buff[j * sizeof(WLAN_STA_INFO_T)];

				if (pInfo->aid && (pInfo->flags & STA_INFO_FLAG_ASOC)) {
					if (!memcmp(cpemac, pInfo->addr, 6)) {
						if(pInfo->TxOperaRate >= 0xA0) {
							set_11ac_txrate(pInfo, txrate, sizeof(txrate));
						} else if((pInfo->TxOperaRate & 0x80) != 0x80) {
							if(pInfo->TxOperaRate % 2) {
								snprintf(txrate, sizeof(txrate), "%d%s",pInfo->TxOperaRate / 2, ".5");
							} else {
								snprintf(txrate, sizeof(txrate), "%d", pInfo->TxOperaRate / 2);
							}
						} else {
							if((pInfo->ht_info & 0x1) == 0) { //20M
								if((pInfo->ht_info & 0x2) == 0) {//long
									for (rateid = 0; rateid < 16; rateid++) {
										if(rate_11n_table_20M_LONG[rateid].id == pInfo->TxOperaRate) {
											snprintf(txrate, sizeof(txrate), "%s", rate_11n_table_20M_LONG[rateid].rate);
											break;
										}
									}
								} else if((pInfo->ht_info & 0x2) == 0x2) {//short
									for(rateid = 0; rateid < 16; rateid++) {
										if(rate_11n_table_20M_SHORT[rateid].id == pInfo->TxOperaRate) {
											snprintf(txrate, sizeof(txrate), "%s", rate_11n_table_20M_SHORT[rateid].rate);
											break;
										}
									}
								}
							} else if((pInfo->ht_info & 0x1) == 0x1) {//40M
								if((pInfo->ht_info & 0x2) == 0) {//long
									for(rateid = 0; rateid < 16; rateid++) {
										if(rate_11n_table_40M_LONG[rateid].id == pInfo->TxOperaRate) {
											snprintf(txrate, sizeof(txrate), "%s", rate_11n_table_40M_LONG[rateid].rate);
											break;
										}
									}
								} else if((pInfo->ht_info & 0x2) == 0x2) {//short
									for(rateid = 0; rateid < 16; rateid++) {
										if(rate_11n_table_40M_SHORT[rateid].id == pInfo->TxOperaRate) {
											snprintf(txrate, sizeof(txrate), "%s", rate_11n_table_40M_SHORT[rateid].rate);
											break;
										}
									}
								}
							}

						}
						break;
					}
				}
			}
		}
		band++;
	}

	free(buff);
	return strtoul(txrate, NULL, 10);
}

static int build_wlsta_trapinfo(struct wl_info_t *psta_info, struct nlkevent_t *pnlk, char *msg, int msglen)
{
	char buf[256];
	struct tm *tm;
	time_t tt;
	int n = 0;
	struct scaled_octet tx, rx;
	char quantity[2][32];
	char tmpMacstr[80];
	struct monitor_sta_t *monitor_sta;
	int event;

	event = (pnlk->event&STA_CONSTAT_MASK);
	monitor_sta = ((struct monitor_sta_t *)&pnlk->event_msg[0]);
#if STAMON_DBG
	printf("\nevent = %d\n", event);
	printf("sta mac[%02X:%02X:%02X:%02X:%02X:%02X]\n",
				monitor_sta->mac[0],monitor_sta->mac[1],monitor_sta->mac[2],
				monitor_sta->mac[3],monitor_sta->mac[4],monitor_sta->mac[5]);
	printf("monitor_sta->link_time = %lu\n", monitor_sta->link_time);
	printf("monitor_sta->tx_only_data_packets = %u\n", monitor_sta->tx_only_data_packets);
	printf("monitor_sta->rx_only_data_packets = %u\n", monitor_sta->rx_only_data_packets);
	printf("monitor_sta->tx_only_data_bytes = %u\n", monitor_sta->tx_only_data_bytes);
	printf("monitor_sta->tx_only_data_bytes_high = %u\n", monitor_sta->tx_only_data_bytes_high);
	printf("monitor_sta->rx_only_data_bytes = %u\n", monitor_sta->rx_only_data_bytes );
	printf("monitor_sta->rx_only_data_bytes_high = %u\n", monitor_sta->rx_only_data_bytes_high);
#endif

	if ( !(tm = get_trapevent_time(&tt, 0)) )
		return 0;

	sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d",
		tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
	msglen -= 1;
	tmpMacstr[0]=0;
	nvram_get_r_def("HW_NIC1_ADDR", tmpMacstr, sizeof(tmpMacstr), NULL);
	if (event == STA_START) {
		n = snprintf(&msg[n], msglen - n, "status=start\r\n");
		n += snprintf(&msg[n], msglen - n, "evt-time=%s\r\n", buf);
		//n += snprintf(&msg[n], msglen-n, "session-time=%lu\r\n", monitor_sta->link_time);
		n += snprintf(&msg[n], msglen - n, "session-time=0\r\n");
		n += snprintf(&msg[n], msglen - n, "ap-mac=%s\r\n", tmpMacstr);
		n += snprintf(&msg[n], msglen - n, "cpe-mac=%s\r\n",ether_ntoa(&monitor_sta->mac[0], 0));
		n += snprintf(&msg[n], msglen - n, "ssid=%s\r\n", psta_info->ssid);
		n += snprintf(&msg[n], msglen - n, "band=%s\r\n", monitor_sta->band);
		n += snprintf(&msg[n], msglen - n, "channel-width=%d\r\n", monitor_sta->bandwidth);
		n += snprintf(&msg[n], msglen - n, "link-rate=%u\r\n", get_cpe_link_rate(monitor_sta->mac));

		syslog(LOG_ALERT, "%s %s Connected %ddBm",
			   psta_info->ssid, ether_ntoa(monitor_sta->mac, ':'), CONV_TO_RSSI(monitor_sta->rssi));
	} else {
		n = snprintf(&msg[n], msglen - n, "status=stop\r\n");
		n += snprintf(&msg[n], msglen - n, "evt-time=%s\r\n", buf);
		n += snprintf(&msg[n], msglen - n, "session-time=%lu\r\n", monitor_sta->link_time);
		n += snprintf(&msg[n], msglen - n, "ap-mac=%s\r\n", tmpMacstr);
		n += snprintf(&msg[n], msglen - n, "cpe-mac=%s\r\n",ether_ntoa(&monitor_sta->mac[0], 0));
		n += snprintf(&msg[n], msglen - n, "ssid=%s\r\n", psta_info->ssid);
		n += snprintf(&msg[n], msglen - n, "band=%s\r\n", monitor_sta->band);
		n += snprintf(&msg[n], msglen - n, "channel-width=%d\r\n", monitor_sta->bandwidth);
		n += snprintf(&msg[n], msglen - n, "link-rate=%s\r\n", monitor_sta->current_tx_rate);
		n += snprintf(&msg[n], msglen - n, "stop-reason=%d\r\n", monitor_sta->reason);
		n += snprintf(&msg[n], msglen - n, "rssi=%d\r\n", CONV_TO_RSSI(monitor_sta->rssi));
		n += snprintf(&msg[n], msglen - n, "conn_sec=%lu\r\n", monitor_sta->assoc_sec);

		n += snprintf(&msg[n], msglen - n, "packet=%u,%u\r\n",
					monitor_sta->rx_only_data_packets, monitor_sta->tx_only_data_packets);	/* APNRTL-238 In/Out */
		n += snprintf(&msg[n], msglen - n, "octet=%u,%u\r\n",
					monitor_sta->rx_only_data_bytes, monitor_sta->tx_only_data_bytes);		/* To maintain unity, uses 'unsigned long' type  */

		tx.ull = monitor_sta->tx_bytes;
		rx.ull = monitor_sta->rx_bytes;
		syslog(LOG_ALERT, "%s %s Disconnected (Tx:%lu/Rx:%lu/Tf:%lu %lusec TxRate=0x%02x %s/%s %ddBm)",
				psta_info->ssid, ether_ntoa(&monitor_sta->mac[0], ':'),
				monitor_sta->tx_packets, monitor_sta->rx_packets, monitor_sta->tx_fail,
				monitor_sta->link_time, monitor_sta->TxOperaRate,
				bytes_meter(&tx, quantity[0], sizeof(quantity[0])),
				bytes_meter(&rx, quantity[1], sizeof(quantity[0])),
				CONV_TO_RSSI(monitor_sta->rssi));
	}

	return n;
}

static int build_fail_sta_trapinfo(struct wl_info_t *psta_info, struct nlkevent_t *pnlk, char *msg, int msglen)
{
	char buf[256];
	struct tm *tm;
	time_t tt;
	int n = 0;
	char tmpMacstr[80] = {0,};
	struct monitor_sta_t *monitor_sta;

	monitor_sta = ((struct monitor_sta_t *)&pnlk->event_msg[0]);

	if ( !(tm = get_trapevent_time(&tt, 0)) )
		return 0;

	snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
		tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
	msglen -= 1;
	nvram_get_r_def("HW_NIC1_ADDR", tmpMacstr, sizeof(tmpMacstr), NULL);

	n = snprintf(&msg[n], msglen - n, "evt-time=%s\r\n", buf);
	n += snprintf(&msg[n], msglen - n, "ap-mac=%s\r\n", tmpMacstr);
	n += snprintf(&msg[n], msglen - n, "cpe-mac=%s\r\n", ether_ntoa(&monitor_sta->mac[0], 0));
	n += snprintf(&msg[n], msglen - n, "band=%s\r\n", monitor_sta->band);
	n += snprintf(&msg[n], msglen - n, "channel=%d\r\n", monitor_sta->channel);
	n += snprintf(&msg[n], msglen - n, "channel-width=%d\r\n", monitor_sta->bandwidth);
	n += snprintf(&msg[n], msglen - n, "fail-reason=%u\r\n", monitor_sta->reason);

	return n;
}

static int get_wlstaevent_info(char *data, int len, struct nlkevent_t *pnlk)
{
	struct iw_event iwe_buf, *iwe;
	char *pos, *end, *custom;
	int msglen;

	iwe = &iwe_buf;
	pos = data;
	end = data + len;
	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		//printf("Wireless event: cmd=0x%x len=%d",iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN)
			return 0;

		custom = pos + IW_EV_POINT_LEN;
		if ( iwe->cmd == IWEVCUSTOM) {
			/* removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			memcpy(dpos, pos + IW_EV_LCP_LEN, sizeof(struct iw_event) - dlen);
		}

		if ( iwe->cmd == IWEVCUSTOM ) {
			if (custom + iwe->u.data.length > end)
				return 0;
			msglen = sizeof(pnlk->event_msg);
			pnlk->event = iwe->u.data.flags;
			pnlk->event_msglen = ((iwe->u.data.length > msglen)? msglen: iwe->u.data.length);
			memcpy(&pnlk->event_msg[0], &custom[0], pnlk->event_msglen);

			return 1;
		}
		pos += iwe->len;
	}
	return 0;
}



static void record_event_time(struct timeval *tv)
{
	struct timespec ts;

	syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
}


#define WL_HANDOVER_MAIN	"wlan0-va3"

static struct wl_info_t *handover_main_index(struct wl_info_t *psta_info)
{
	unsigned int i;

	//5G Handover wlan
	i = 0;
	for ( i=0; i < MAX_MONITOR_WLINTF; i++) {
		if ( !strcmp(psta_info[i].ifname, WL_HANDOVER_MAIN) )
			return (&psta_info[i]);
	}
	return NULL;
}



#define HO_AUTO		1
#define HO_MANUAL	2
#define HO_BOTH		4
int is_sta_handover_success(struct wl_info_t *psta_info, int evtidx, unsigned int sta_idx, struct timeval *HO_difftime)
{
	FILE *fp = NULL; // APACRTL-485
	struct wl_info_t *wl_ho = NULL;
	struct timeval HO_stime, HO_etime, HO_okTime;
	int handover_ok = 0, manual_handover = 0;
	int HO_mode, state;

	/*Only wlan0-va3 -> wlan1(*) */
	if (evtidx != 5)
		return 0;

	if ( !(wl_ho = handover_main_index(&psta_info[0])) )
		return 0;

	if ( wl_ho->conhist[sta_idx].state == STA_EMPTY )
		return 0;

	if ( memcmp(&wl_ho->conhist[sta_idx].mac, &psta_info[evtidx].conhist[sta_idx].mac, 6) )
		return 0;

	HO_mode = nvram_atoi("x_handover_mode", HO_MANUAL);
	manual_handover = wl_ho->conhist[sta_idx].handover;
	state = wl_ho->conhist[sta_idx].state;
	memcpy(&HO_stime, &wl_ho->conhist[sta_idx].evtime, sizeof(struct timeval));
	memcpy(&HO_etime, &psta_info[evtidx].conhist[sta_idx].evtime, sizeof(struct timeval));
	//clear old handover
	memset(&wl_ho->conhist[sta_idx], 0, sizeof(struct sta_conhist_t));

	timersub(&HO_etime, &HO_stime, HO_difftime);
	HO_okTime.tv_sec = nvram_atoi("x_handover_oktime", 10); //default 10sec // APACRTL-485
	HO_okTime.tv_usec = 0;
	handover_ok = !(timercmp(HO_difftime, &HO_okTime, >));
	if ( (HO_mode == HO_MANUAL) && !manual_handover ) {
		handover_ok = 0;
	} else if ( (HO_mode == HO_AUTO) && manual_handover ) {
		handover_ok = 0;
	}
	syslog(LOG_INFO, "STA %s handover(%s) in mode(%s)(%ld.%ld)|(%d)sec...(%s)",
						ether_ntoa(&psta_info[evtidx].conhist[sta_idx].mac[0], ':'),
						((manual_handover)?"manual":"auto"),
						(HO_mode==1)?("auto"):((HO_mode==2)?("manual"):("both")),
						HO_difftime->tv_sec, (HO_difftime->tv_usec/1000),
						HO_okTime.tv_sec, ((handover_ok)?"success": "---") );

/* APACRTL-485 */
	if (handover_ok) {
		fp = fopen("/tmp/.handover_info", "w");
		if (fp) {
			fprintf(fp, "%s %ld.%ld\n", ether_ntoa(&psta_info[evtidx].conhist[sta_idx].mac[0], NULL),
					HO_difftime->tv_sec, (HO_difftime->tv_usec/1000));
			fclose(fp);
		}
	}

	return handover_ok;
}



static __inline__
unsigned int wlsta_mac_hash(unsigned char *mac)
{
	unsigned char x;

	x = mac[3] ^ mac[4] ^ mac[5];

	x &= MAX_SUPPLICANT_NUM;

	return (x < MAX_SUPPLICANT_NUM) ? x : 0;
}



static int manage_sta_monitor(struct wl_info_t *psta_info, struct nlkevent_t *pnlk, int evtidx)
{
	struct monitor_sta_t *monitor_sta;
	unsigned int sta_idx;
	int launch_trap = 0;
	int event;
	int handover_sta = 0;
	struct timeval s_time;
	int msglen;
	char msg[1024] = {0,};

	event = (pnlk->event&STA_CONSTAT_MASK);
	handover_sta = (pnlk->event&STA_HANDOVER_MASK);
	monitor_sta = ((struct monitor_sta_t *)&pnlk->event_msg[0]);
	sta_idx = wlsta_mac_hash(&monitor_sta->mac[0]);

	if (event == STA_FAIL) {
		if ( (msglen = build_fail_sta_trapinfo(psta_info, pnlk, msg, sizeof(msg))) )
			send_sta_fail_trap(msg, msglen);
		return launch_trap;
	}

	if ( event == STA_STOP ) {
		if ( psta_info[evtidx].conhist[sta_idx].state == STA_START &&
			 !memcmp(psta_info[evtidx].conhist[sta_idx].mac, monitor_sta->mac, 6) ) {
			launch_trap = 1;

			if ( evtidx == 4/*wlan0-va3*/ ) {
				psta_info[evtidx].conhist[sta_idx].handover = handover_sta;
				psta_info[evtidx].conhist[sta_idx].state = event;
				record_event_time(&psta_info[evtidx].conhist[sta_idx].evtime);
			} else {
				memset(&psta_info[evtidx].conhist[sta_idx], 0, sizeof(struct sta_conhist_t));
			}
		}
	} else {
		launch_trap = 1;
		psta_info[evtidx].conhist[sta_idx].state = STA_START;
		memcpy(&psta_info[evtidx].conhist[sta_idx].mac[0], &monitor_sta->mac[0], 6);
		record_event_time(&psta_info[evtidx].conhist[sta_idx].evtime);
		if ( is_sta_handover_success(psta_info, evtidx, sta_idx, &s_time) )
			yexecl(NULL, "sh -c \"snmp -m 9 &\"");
	}

	return launch_trap;
}



void trap_wl_stainfo(struct wl_info_t *psta_info, struct nlkevent_t *pnlk)
{
	int msglen;
	char msg[1024];
	int event;

	event = (pnlk->event&STA_CONSTAT_MASK);
	if ( (msglen=build_wlsta_trapinfo(psta_info, pnlk, msg, sizeof(msg))) )
		send_wlall_status_trap(msg, msglen, ((event)?WIFI_ON_TRAP:WIFI_OFF_TRAP));
}



static void catcher_stainfo_classification(struct wl_info_t *pwl_info, struct ifinfomsg *ifi, unsigned char *rawbuf, size_t rawbuf_len)
{
	int attrlen, rta_len;
	struct rtattr *attr;
	int i, match_intf = -1;
	struct nlkevent_t nlkevent;

	for ( i= 0; i < MAX_MONITOR_WLINTF; i++) {
		if ( pwl_info[i].ifindex < 0)
			continue;
		if ( pwl_info[i].ifindex == ifi->ifi_index) {
			match_intf = i;
			break;
		}
	}

	if ( match_intf < 0 )
		return;

	attrlen = rawbuf_len;
	attr = (struct rtattr *) rawbuf;

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			if ( get_wlstaevent_info( ((char *) attr) + rta_len, (attr->rta_len - rta_len), &nlkevent) ) {
				if ( manage_sta_monitor(&pwl_info[0], &nlkevent, match_intf) ) {
					if ( is_alive_wanline() ) {
						trap_wl_stainfo(&pwl_info[match_intf], &nlkevent);
					}
				}
				break;
			}
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}



int init_wlmonitor(struct wl_info_t *pwl_info)
{
	int i, n, diff;
	struct ifreq ifr;
	int ioctl_sock;
	char buf[80];
	bss_info bss;
	FILE *fp = NULL;

	fp = fopen("/var/tmp/sta_monitor", "w");
	if ( (ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}
	for ( i = 0; i < MAX_MONITOR_WLINTF; i++) {
		n = i;
		if ( !pwl_info[i].monitor )
			continue;
		buf[0] = 0;
		if ( (diff=(i-5)) >= 0)
			n = diff;
		if ( n == 0 )
			sprintf(buf, "WLAN%d_WLAN_DISABLED", ((diff < 0 )?0:1));
		else
			sprintf(buf, "WLAN%d_VAP%d_WLAN_DISABLED", ((diff < 0 )?0:1), (n-1));

		if ( nvram_match(buf, "1") )
			continue;

		memset(&ifr, 0, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", pwl_info[i].ifname);

		if (ioctl(ioctl_sock, SIOCGIFINDEX, &ifr) != 0) {
			perror("ioctl(SIOCGIFINDEX)");
			continue;
		}
		pwl_info[i].ifindex = ifr.ifr_ifindex;
		getWlBssInfo(pwl_info[i].ifname, &bss);
		pwl_info[i].ssid[0] = 0;
		sprintf(&pwl_info[i].ssid[0], "%s", bss.ssid);

		if (fp)
			fprintf(fp, "%s\n", pwl_info[i].ifname);
	}
	if (fp)
		fclose(fp);
	close(ioctl_sock);
	return 0;
}



int netlink_fd(void)
{
	int s;
	struct sockaddr_nl local;

	if ( (s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0 ) {
		perror("socket(PF_NETLINK,SOCK_RAW,NETLINK_ROUTE)");
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;

	if (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
		perror("bind(netlink)");
		close(s);
		return -1;
	}
	return s;
}



void catcher_stainfo_fromnetlink(struct wl_info_t *pwl_info, int nfs)
{
	struct nlmsghdr *h;
	struct sockaddr_nl from;
	int fromlen;
	char buf[8192];
	int left;
	int len, plen;

	fromlen = sizeof(from);
	if ( (left = recvfrom(nfs, buf, sizeof(buf), MSG_DONTWAIT,
				(struct sockaddr *) &from, &fromlen)) < 0 ) {
		if (errno != EINTR && errno != EAGAIN)
			perror("recvfrom(netlink)");
		return;
	}
	h = (struct nlmsghdr *) buf;
	while (left >= (int) sizeof(*h)) {
		len = h->nlmsg_len;
		plen = len - sizeof(*h);
		if (len > left || plen < 0) {
			printf("Malformed netlink message: len=%d left=%d plen=%d", len, left, plen);
			break;
		}
		switch (h->nlmsg_type) {
			case RTM_NEWLINK:
				catcher_stainfo_classification(pwl_info, NLMSG_DATA(h),
							(unsigned char *) NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct ifinfomsg)),
							NLMSG_PAYLOAD(h, sizeof(struct ifinfomsg)));
				break;
			default:
				break;
		}
		len = NLMSG_ALIGN(len);
		left -= len;
		h = (struct nlmsghdr *) ((char *) h + len);
	}
	if (left > 0)
		printf("%d extra bytes in the end of netlink ", left);
}

#endif
