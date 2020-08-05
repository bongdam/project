/* jihyun@davo150617 jcode#2 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <error.h>
#include <sys/stat.h>
#include <linux/wireless.h>
#include <8192cd.h>
#include <bcmnvram.h>
#include <libytool.h>
#include "instrument.h"
#include "laborer.h"
#include "smart_wlreset.h"

static struct wl_reset_t g_wl_reset;
int g_wl_reset_enable;
static char g_wl_reset_wlstatebit[2];
static struct wl_data_t g_pre_data[2][5], g_now_data[2][5];
static unsigned int random_time = 0;

#define WL_RESET_INTERVAL_DAY	8
#define WL_RESET_TRIGER_S		3	//03 AM
#define WL_RESET_TRIGER_S_M		10	//10
#define WL_RESET_TRIGER_E		5	//05 AM
#define WL_RESET_TRIGER_E_M		0	//05 AM
#define WL_RESET_ONE_DAY		1
#define DEFAULT_TRAFFIC_BYTE    512000	//500kbytes
#define RECORDING_TIME_SEC		60
#define DEFAULT_TIME_GAP		6600

void init_smart_wlanreset(void);
void poll_smart_wlanreset(void);

struct labor_house family_smartreset = {
	init_smart_wlanreset,
	poll_smart_wlanreset,
	&g_wl_reset_enable,
};

static void get_wlanintf_name(int slot, int index, char *wlname, int wlname_len)
{
	if (!wlname)
		return;

	if (index == 0)
		snprintf(wlname, wlname_len, "wlan%d", slot);
	else
		snprintf(wlname, wlname_len, "wlan%d-va%d", slot, index - 1);
}

static int normal_mydate(void)
{
	return (!access("/tmp/ntp_ok", F_OK));
}

static int get_wlan_traffic_stats(char *ifname, struct wl_data_t *wd)
{
	int fd, rc;
	struct iwreq wrq;
	struct wlan_traffic_stats_t wts;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&wts;
	wrq.u.data.length = sizeof(wts);
	wrq.u.data.flags = RTL8192CD_IOCTL_WLAN_STATS;

	if ((rc = ioctl(fd, SIOCIWCUSTOM, &wrq)) < 0)
		perror("ioctl error");

	if (!rc) {
		wd->rx.high = wts.rx_only_data_bytes_high;
		wd->rx.low = wts.rx_only_data_bytes;

		wd->tx.high = wts.tx_only_data_bytes_high;
		wd->tx.low = wts.tx_only_data_bytes;
	}
	close(fd);

	return rc;
}

static unsigned int time_calc(void)
{
	struct tm poll, *t;
	time_t ctime;
	time_t stime, etime;
	unsigned int calc;

	memset(&poll, 0, sizeof(struct tm));
	time(&ctime);
	t = localtime(&ctime);

	poll.tm_year = t->tm_year;
	poll.tm_mon = t->tm_mon;
	poll.tm_mday = t->tm_mday;
	poll.tm_hour = g_wl_reset.start;
	poll.tm_min = g_wl_reset.start_m;
	stime = mktime(&poll);

	poll.tm_hour = g_wl_reset.end;
	poll.tm_min = g_wl_reset.end_m;
	etime = mktime(&poll);

	if ((calc = (etime - stime)) < 1)
		calc = DEFAULT_TIME_GAP;

	return calc;
}

static unsigned int random_start_time(void)
{
	char value[24] = {0,};
	char temp[3] = {0,};
	unsigned char hwAddr[6] = {0,};
	int i, j;
	unsigned int seed, range;
	FILE *fp;
	unsigned int t[4] = {0,};

	nvram_get_r_def("HW_NIC1_ADDR", value, sizeof(value), "0023aa112233");
	for (i = 0, j = 0; i < 12; i += 2) {
		memcpy(temp, &value[i], 2);
		hwAddr[j++] = (char)strtol(temp, NULL, 16);
	}
	fp = fopen("/proc/uptime", "r");
	if (fp) {
		fscanf(fp, "%u.%u %u.%u", &t[0], &t[1], &t[2], &t[3]);
		fclose(fp);
	}
	seed = hwAddr[3] + hwAddr[4] + hwAddr[5] + t[0] + t[1];
	srand(seed);
	range = time_calc() * 0.75;
	return (unsigned int)(random() % range);
}

static long app_wl_reset_polling_time_day(const int interval_day)
{
	struct tm now_clock, start_triger_clk;
	long t_start, time_gap;
	unsigned int interval = 0;
	long now;

	interval = interval_day;
	if (interval < 0)
		interval = 0;

	now = time(NULL);
	now_clock = *(localtime(&now));

	start_triger_clk = now_clock;

	start_triger_clk.tm_hour = g_wl_reset.start;
	start_triger_clk.tm_min = g_wl_reset.start_m;
	start_triger_clk.tm_sec = 0;

	random_time = random_start_time();

	t_start = mktime(&start_triger_clk) + random_time;

	if (now < t_start) {
		time_gap = (t_start - now);
		return ((now + time_gap) + (interval * 86400));
	}
	interval += 1;
	time_gap = (now - t_start);
	return (((now + interval * 86400) - time_gap));
}

static char *get_data_size_converter(char *buf, unsigned long h, unsigned long l)
{
	int data_octet[3];
	unsigned int giga = 1073741824;
	unsigned int mega = 1048576;
	unsigned int kilo = 1024;
	unsigned int mod_temp = 0;
	int n = 0;

	mod_temp = l;
	buf[0] = 0;
	memset(data_octet, 0, sizeof(data_octet));
	if (h > 0)
		data_octet[0] = h * 4;
	if (l >= giga) {
		data_octet[0] += (l / giga);
		mod_temp = (l % giga);
	}
	if (mod_temp >= mega) {
		data_octet[1] = (mod_temp / mega);
		mod_temp = (mod_temp % mega);
	}
	if (mod_temp >= kilo) {
		data_octet[2] = (mod_temp / kilo);
		mod_temp = (mod_temp % kilo);
	}

	if (data_octet[0] > 0)
		n += sprintf(&buf[n], "%uG ", data_octet[0]);
	if (data_octet[1] > 0)
		n += sprintf(&buf[n], "%uM ", data_octet[1]);
	if (data_octet[2] > 0)
		n += sprintf(&buf[n], "%uK ", data_octet[2]);
	if (mod_temp < kilo)
		n += sprintf(&buf[n], "%ubyte", mod_temp);

	return buf;
}

static int running_dataTraffic(void)
{
	unsigned int i, v;
	char name[IFNAMSIZ], buf[128], buf1[128];
	struct wl_data_t *pdata;
	unsigned long rx_diff_byte, tx_diff_byte;
	unsigned long rx_high_diff_byte, tx_high_diff_byte;
	unsigned long tmp;

	if (!g_wl_reset.monitor) {
		for (i = 0; i < 2; i++) {
			memset(&g_pre_data[i], 0, sizeof(g_pre_data[i]));
			memset(&g_now_data[i], 0, sizeof(g_now_data[i]));
		}
	}
	for (i = 0; i < 2; i++) {
		for (v = 0; v < 5; v++) {
			if (!(g_wl_reset_wlstatebit[i] & (1 << v)))
				continue;
			pdata = ((g_wl_reset.monitor == 0) ? &g_pre_data[i][v] : &g_now_data[i][v]);
			get_wlanintf_name(i, v, name, sizeof(name));
			get_wlan_traffic_stats(name, pdata);
		}
	}

	if (!g_wl_reset.monitor) {
		g_wl_reset.monitor = 1;
		g_wl_reset.next_poll_time = time(NULL) + RECORDING_TIME_SEC;
		return 0;
	}
	g_wl_reset.monitor = 0;
	for (i = 0; i < 2; i++) {
		for (v = 0; v < 5; v++) {
			if (!(g_wl_reset_wlstatebit[i] & (1 << v)))
				continue;
			//check rx
			rx_high_diff_byte = (g_now_data[i][v].rx.high - g_pre_data[i][v].rx.high);
			if (g_now_data[i][v].rx.low >= g_pre_data[i][v].rx.low) {
				rx_diff_byte = (g_now_data[i][v].rx.low - g_pre_data[i][v].rx.low);
			} else {
				tmp = g_pre_data[i][v].rx.low - g_now_data[i][v].rx.low;
				if (rx_high_diff_byte > 0) {
					rx_high_diff_byte -= 1;
					rx_diff_byte = 0xffffffff - tmp;
				} else {
					perror("Rx stastics of wireless error");
				}
			}
			//check tx
			tx_high_diff_byte = (g_now_data[i][v].tx.high - g_pre_data[i][v].tx.high);
			if (g_now_data[i][v].tx.low >= g_pre_data[i][v].tx.low) {
				tx_diff_byte = (g_now_data[i][v].tx.low - g_pre_data[i][v].tx.low);
			} else {
				tmp = g_pre_data[i][v].tx.low - g_now_data[i][v].tx.low;
				if (tx_high_diff_byte > 0) {
					tx_high_diff_byte -= 1;
					tx_diff_byte = 0xffffffff - tmp;
				} else {
					perror("Rx stastics of wireless error");
				}
			}
			syslog(LOG_INFO, "[smart reset][%d.%d] (Tx: %s, Rx: %s) %u KByte",
			       i, v,
			       get_data_size_converter(buf, tx_high_diff_byte, tx_diff_byte),
			       get_data_size_converter(buf1, rx_high_diff_byte, rx_diff_byte), (g_wl_reset.bytes / 1024));

			if (rx_high_diff_byte || tx_high_diff_byte)
				return 1;

			if ((rx_diff_byte > g_wl_reset.bytes) || (tx_diff_byte > g_wl_reset.bytes))
				return 1;
		}
	}
	return 0;
}

int nvram_get_int(char *param, int dft)
{
	char *p = nvram_get(param);
	return (p && p[0]) ? atoi(p) : dft;
}

static void write_log(long next_time)
{
	struct tm triger_time;

	triger_time = *(localtime(&next_time));
	syslog(LOG_INFO, "[smart reset]Be scheduled checking in time(%4d.%02d.%02d %02d:%02d:%02d)",
	       triger_time.tm_year + 1900, triger_time.tm_mon + 1, triger_time.tm_mday,
	       triger_time.tm_hour, triger_time.tm_min, triger_time.tm_sec);
}

void init_smart_wlanreset(void)
{
	int i, v;
	char buffer[80], tmp[80];
	char *sh, *eh, *sm, *em;

	memset(&g_wl_reset, 0, sizeof(g_wl_reset));
	g_wl_reset.start_ready = 0;
	memset(&g_wl_reset_wlstatebit[0], 0, sizeof(g_wl_reset_wlstatebit));
	g_wl_reset_enable = nvram_get_int("x_wlan_reset_enable", 1);
	g_wl_reset.interval = nvram_get_int("x_wlan_reset_interval_day", 8);

	nvram_get_r("x_wlan_reset_triger_time", tmp, sizeof(tmp));
	g_wl_reset.start = WL_RESET_TRIGER_S;
	g_wl_reset.start_m = WL_RESET_TRIGER_S_M;
	g_wl_reset.end = WL_RESET_TRIGER_E;
	g_wl_reset.end_m = WL_RESET_TRIGER_E_M;

	em = &tmp[0];
	sm = strsep(&em, "\r\n\t-");
	if (sm) {
		sh = strsep(&sm, "\r\n\t:");
		if (sh)
			g_wl_reset.start = strtoul(sh, NULL, 10);
		if (sm)
			g_wl_reset.start_m = strtoul(sm, NULL, 10);
	}
	if (em) {
		eh = strsep(&em, "\r\n\t:");
		if (eh)
			g_wl_reset.end = strtoul(eh, NULL, 10);
		if (em)
			g_wl_reset.end_m = strtoul(em, NULL, 10);
	}

	g_wl_reset.bytes = (nvram_get_int("x_wlan_reset_bw_kbps", 500) * 1000) / 8;
	for (i = 0; i < 2; i++) {
		for (v = 0; v < 5; v++) {
			if (v == 0)
				sprintf(tmp, "WLAN%d_WLAN_DISABLED", i);
			else
				sprintf(tmp, "WLAN%d_VAP%d_WLAN_DISABLED", i, (v - 1));
			nvram_get_r(tmp, buffer, sizeof(buffer));
			if (buffer[0] == '0')
				g_wl_reset_wlstatebit[i] |= (1 << v);
		}
	}
}

static unsigned int smart_wlanreset_endtime_sec(void)
{
	return (g_wl_reset.next_poll_time + time_calc() - random_time);
}

void poll_smart_wlanreset(void)
{
	long now;
	static unsigned int check_ntp = 0;
	static int wlreset_retry = 0;

	if (!g_wl_reset.start_ready) {
		if (!check_ntp && !(check_ntp = normal_mydate()))
			return;
		syslog(LOG_INFO, "[smart reset]Start process...[uptime:%u/%u~%u]",
		       g_wl_reset.interval, g_wl_reset.start, g_wl_reset.end);
		g_wl_reset.start_ready = 1;
		g_wl_reset.next_poll_time = app_wl_reset_polling_time_day(g_wl_reset.interval);
		g_wl_reset.try_limit_time = smart_wlanreset_endtime_sec();
		write_log(g_wl_reset.next_poll_time);
	}
	now = time(NULL);
	// checked each pass 8days, do reset wlan interface in 03:00 am ~ 05:00
	if (now >= g_wl_reset.next_poll_time) {
		// checked wireless traffic
		if (running_dataTraffic()) {
			// when using traffic, retry after 5min
			g_wl_reset.next_poll_time = time(NULL) + 300;

			if ((g_wl_reset.try_limit_time &&
					(g_wl_reset.next_poll_time > g_wl_reset.try_limit_time)) || (wlreset_retry >= 2)) {
				g_wl_reset.next_poll_time = app_wl_reset_polling_time_day(0);
				g_wl_reset.try_limit_time = smart_wlanreset_endtime_sec();
				yexecl(NULL, "sh -c \"snmp -m 7 traffic &\"");
				wlreset_retry = 0;
				syslog(LOG_INFO, "[smart reset]Detect traffic over time, delay 1day");
				write_log(g_wl_reset.next_poll_time);
				return;
			}

			syslog(LOG_INFO, "[smart reset]Detect traffic, retry to checking after 5min");
			wlreset_retry++;
			return;
		}
		if (g_wl_reset.monitor)
			return;

		//reset wlan interface
		//check to main wlan interface setting
		if ((g_wl_reset_wlstatebit[0] & 0x1) || (g_wl_reset_wlstatebit[1] & 0x1)) {
			syslog(LOG_INFO, "[smart reset]Doing Smart reset");
			yexecl(NULL, "sh -c \"snmp -m 7 &\"");
			yexecl(NULL, "sh -c \"smartreset --wl0 %#x --wl1 %#x &\"", g_wl_reset_wlstatebit[0], g_wl_reset_wlstatebit[1]);
		} else
			syslog(LOG_INFO, "[smart reset]wlan0 wlan1 disabled");

		wlreset_retry = 0;
		g_wl_reset.next_poll_time = app_wl_reset_polling_time_day(g_wl_reset.interval);
		g_wl_reset.try_limit_time = smart_wlanreset_endtime_sec();
		write_log(g_wl_reset.next_poll_time);
	}
}
