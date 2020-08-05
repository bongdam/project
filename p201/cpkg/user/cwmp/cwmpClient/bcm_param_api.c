#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <assert.h>
//#include <net/if.h>
#include <typedefs.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <bcmnvram.h>
#include <sys/un.h>
#include <sys/sysinfo.h>
#include <strtok_s.h>
#include <syslog.h>

typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int16_t u16;
typedef u_int8_t u8;

#include <linux/sockios.h>
#include <linux/ethtool.h>

#include <linux/wireless.h>

#include <apmib_defs.h>
#include <8192cd_common.h>
#define _LINUX_LIST_H_	// To avoid bool redefinition error
#include <apmib.h>
#include <sys/signal.h>
#include <shutils.h>
#include <libytool.h>
#include <publicfunc.h>
#include <brdio.h>

#include "bcm_param_api.h"
#include "utf8_util.h"

#define ETHER_ISNULLADDR(ea)    ((((const uint8 *)(ea))[0] | \
                                  ((const uint8 *)(ea))[1] | \
                                  ((const uint8 *)(ea))[2] | \
                                  ((const uint8 *)(ea))[3] | \
                                  ((const uint8 *)(ea))[4] | \
                                  ((const uint8 *)(ea))[5]) == 0)
#ifdef __CONFIG_LGUPLUS__
#define DHCPD_LEASE_FILE "/var/lib/misc/udhcpd.leases"
#else
#define DHCPD_LEASE_FILE "/tmp/udhcpd0.leases"
#endif

#ifndef MAX_WL_INTF
#define MAX_WL_INTF 2
#endif
#ifndef MAX_WL_BSS
#define MAX_WL_BSS DV_MAX_WL_BSS
#endif

static wl_client_info_t info[128];
static _neighap_info_t neigh_ap[MAXIDX][128];
static int neigh_ap_num[MAXIDX];
static int neigh_ap_scanned_time[MAXIDX];

#define NVRAM_STATIC_STR "0"
#define NVRAM_DHCP_STR "1"

struct wanconfig_t {
	int mode;
	char ip[IP_BUF_LEN];
	char nm[IP_BUF_LEN];
	char gw[IP_BUF_LEN];
	int set;
	int err;
};

struct lanconfig_t {
	char ip[IP_BUF_LEN];
	char nm[IP_BUF_LEN];
	int set;
	int err;
};

struct wanconfig_t wanconfig;
struct lanconfig_t lanconfig;

/*-----------------------------------------------------------------------------
 *  util functions
 *-----------------------------------------------------------------------------*/
void str_lower(char *p)
{
	int c;
	while ((c = *p))
		* p++ = tolower(c);
}

/*-----------------------------------------------------------------------------
 *  static functions
 *-----------------------------------------------------------------------------*/
static int ishex(const char *s)
{
	int c;
	while ((c = *s++)) {
		if (!((c >= '0' && c <= '9') ||
		      (c >= 'A' && c <= 'F') ||
		      (c >= 'a' && c <= 'f')))
			return 0;
	}
	return 1;
}

static int ishex_char(char c)
{
	return (((c >= '0') && (c <= '9')) ||
	        ((c >= 'A') && (c <= 'F')) ||
	        ((c >= 'a') && (c <= 'f')));
}

#if 0
static int find_end(char *p, int max_index)
{
	int i;

	if (max_index < 0)
		return 0;

	for (i = max_index; i >= 0; i--) {
		if (p[i] != 0) {
			return i;
		}
	}
	return 0;
}
#endif

static int find_ip_with_mac(const char *srcMac, char *val, int bufsz)
{
	int fd;
	FILE *fp = NULL;
	char line[128] = {0, };
	char *argv[] = { "killall", "-SIGUSR1", "udhcpd", NULL };
	char strip[20] = {0, }, strhwaddr[20] = {0, };

	if (IS_BRIDGE_MODE) {
		snprintf(val, bufsz, "%s", "0.0.0.0");
		return 0;
	}

	val[0] = 0;
	yexecv(argv, NULL, 5, NULL);

	fd = open(DHCPD_LEASE_FILE, O_RDONLY);
	if (fd >= 0) {
		struct lease_t lease;
		unsigned int expires;

		while (read(fd, &lease, sizeof(lease)) > 0) {
			if (ETHER_ISNULLADDR(lease.chaddr))
				continue;
			expires = ntohl(lease.expires);
			if (expires == 0)
				continue;
			if (!STRNCASECMP(srcMac, ether_etoa(lease.chaddr, strhwaddr))) {
				struct in_addr addr;

				addr.s_addr = lease.yiaddr;
				snprintf(val, bufsz, "%s", inet_ntoa(addr));
				break;
			}
		}
		close(fd);
	}
	if (val[0] != 0)
		return 0;

	fp = fopen("/proc/net/arp", "r");
	if (fp == NULL)
		return -1;
	fgets(line, sizeof(line), fp);	/* consume title line */
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%19s %*x %*x %19s", strip, strhwaddr) == 2 &&
		    STRNCASECMP(strhwaddr, srcMac) == 0) {
			snprintf(val, bufsz, "%s", strip);
			break;
		}
	}
	fclose(fp);

	return 0;
}

static int is_valid_netmask(char *netmask)
{
	unsigned int t = 0;
	int i = 0;
	unsigned int class = 0;
	struct in_addr nm;

	if (!netmask || STRLEN(netmask) < 1)
		return 0;

	memset((void *)&nm, 0, sizeof(struct in_addr));

	if (!inet_aton(netmask, &nm))
		return 0;

	class = htonl(0xff000000);
	t = nm.s_addr & class;
	if (t != class)
		return 0;

	class = htonl(0x00ff0000);
	t = nm.s_addr & class;
	if (t != 0) {
		class = htonl(0x00800000);
		for (i = 0; i < 8; i++) {

			if (class == t)
				break;

			class = class >> 1;
			class = class + htonl(0x00800000);
		}
		if (i > 7)
			return 0;
	}

	class = htonl(0x0000ff00);
	t = nm.s_addr & class;
	if (t != 0) {
		class = htonl(0x00008000);
		for (i = 0; i < 8; i++) {

			if (class == t)
				break;

			class = class >> 1;
			class = class + htonl(0x00008000);
		}
		if (i > 7)
			return 0;
	}

	class = htonl(0x000000ff);
	t = nm.s_addr & class;
	if (t != 0) {
		class = htonl(0x00000080);
		for (i = 0; i < 8; i++) {
			if (class == t)
				break;

			class = class >> 1;
			class = class + htonl(0x00000080);
		}
		if (i > 7)
			return 0;
	}

	return 1;
}

static inline int iw_get_ext(
        int skfd,            /* Socket to the kernel */
        char * ifname,       /* Device name */
        int request,         /* WE ID */
        struct iwreq * pwrq) /* Fixed part of the request */
{
	/* Set device name */
	strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
	/* Do the request */
	return (ioctl(skfd, request, pwrq));
}

static int getWlSiteSurveyRequest(char *interface, int *pStatus)
{
#ifndef NO_ACTION
	int skfd = 0;
	struct iwreq wrq;
	unsigned char result;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1)
		return -1;

	/* Get wireless name */
	if (iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
		/* If no wireless name : no wireless extensions */
		close(skfd);
		return -1;
	}
	wrq.u.data.pointer = (caddr_t)&result;
	wrq.u.data.length = sizeof(result);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLSCANREQ, &wrq) < 0) {
		//close( skfd );
		//return -1;
	}
	close(skfd);

	if (result == 0xff)
		*pStatus = -1;
	else
		*pStatus = (int)result;
#else
	*pStatus = -1;
#endif
#ifdef CONFIG_RTK_MESH
	// ==== modified by GANTOE for site survey 2008/12/26 ====
	return (int) * (char *)wrq.u.data.pointer;
#else
	return 0;
#endif
}

static int getWlSiteSurveyResult(char *interface, SS_STATUS_Tp pStatus)
{
#ifndef NO_ACTION
	int skfd = 0;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1)
		return -1;
	/* Get wireless name */
	if (iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
		/* If no wireless name : no wireless extensions */
		close(skfd);
		return -1;
	}
	wrq.u.data.pointer = (caddr_t)pStatus;

	if (pStatus->number == 0)
		wrq.u.data.length = sizeof(SS_STATUS_T);
	else
		wrq.u.data.length = sizeof(pStatus->number);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSDB, &wrq) < 0) {
		close(skfd);
		return -1;
	}
	close(skfd);
#else
	return -1;
#endif
	return 0;
}

static int getWlBssInfo(char *interface, bss_info *pInfo, int *chwidth, int *sideband)
{
#ifndef NO_ACTION
	int skfd = 0;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1)
		return -1;
	/* Get wireless name */
	if (iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0)
		/* If no wireless name : no wireless extensions */
	{
		close(skfd);
		return -1;
	}

	wrq.u.data.pointer = (caddr_t)pInfo;
	wrq.u.data.length = sizeof(bss_info);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSINFO, &wrq) < 0) {
		close(skfd);
		return -1;
	}
	close(skfd);
	if (chwidth) {
		FILE *f;
		char buf[strlen(interface) + sizeof("/proc//mib_11n")];
		char *line = NULL;
		size_t len = 0;

		sprintf(buf, "/proc/%s/mib_11n", interface);
		f = fopen(buf, "r");
		if (f) {
			*chwidth = *sideband = -1;
			while (getline(&line, &len, f) != -1) {
				if (*chwidth < 0 && strstr(line, "currBW:"))
					sscanf(line, "%*s %d", chwidth);
				if (*sideband < 0 && strstr(line, "2ndchoffset:")) {
					sscanf(line, "%*s %s", buf);
					if (!strcmp(buf, "above"))
						*sideband = 'A';
					else if (!strcmp(buf, "below"))
						*sideband = 'B';
					else
						*sideband = 0;
				}
				if (*chwidth > -1 && *sideband > -1)
					break;
			}
			fclose(f);
		}
		free(line);
	}
#else
	memset(pInfo, 0, sizeof(bss_info));
#endif

	return 0;
}

unsigned int rand_seed(void)
{
	int i;
	unsigned int seed = 0;
	char buf[32] = "";

	get_wan_macaddr(buf, sizeof(buf), LOWER);
	for (i = 0; i < STRLEN(buf); i++)
		seed += buf[i];

	memset(buf, 0, sizeof(buf));
	get_serial(buf, sizeof(buf));
	for (i = 0; i < STRLEN(buf); i++)
		seed += buf[i];

	seed += ygettime(NULL);

	return seed;
}

static int conv_ip_to_host_order(char *ip, uint32_t *data)
{
	struct in_addr addr;

	if (!ip || !data)
		return 0;

	memset(&addr, 0, sizeof(struct in_addr));
	if (!inet_aton(ip, &addr))
		return 0;

	*data = ntohl(addr.s_addr);

	return 1;
}

static int conv_host_order_to_ip(char *ip, int ipsz, uint32_t data)
{
	struct in_addr addr;

	if (!ip)
		return 0;

	memset(&addr, 0, sizeof(struct in_addr));
	addr.s_addr = htonl(data);
	snprintf(ip, ipsz, "%s", inet_ntoa(addr));

	return 1;
}

static int check_wifi_chan(int radio, int ch)
{
	if (radio < 0 || radio >= MAXIDX)
		return 0;

	if (radio == 1) {
		if (ch < 1 || ch > 13)
			return 0;
	} else {
		if (ch < 36 || ch > 161)
			return 0;
	}

	return 1;
}

/*-----------------------------------------------------------------------------
 *  public functions
 *-----------------------------------------------------------------------------*/
char *get_wan_name(void)
{
	if (IS_BRIDGE_MODE) {
#if 0
		if (!nvram_atoi("WLAN0_VAP4_WLAN_DISABLED", 0))
			return "wlan0-vxd";
		else if (!nvram_atoi("WLAN0_VAP4_WLAN_DISABLED", 0))
			return "wlan1-vxd";
		else
			return "br0";
#endif
		return "br0";
	} else {
		return "eth1";
	}
}

char *get_lan_name(void)
{
	return "br0";
}

void get_wlan_idxes(int objidx, int *wl_idx, int *wl_subidx)
{
	//2.4 GHz : 1, 3, 5, 7
	//5 GHz : 2, 4, 6, 8

	if (wl_idx && wl_subidx) {
		*wl_idx = objidx % 2;
		*wl_subidx = ((objidx + 1) / 2) - 2;
	}
}

char *get_wlan_ifname_from_idx(char *buf, int bufsz, int idx, int subidx)
{
	if (buf == NULL)
		return NULL;

	if (subidx == -1)
		snprintf(buf, bufsz, "wlan%d", idx);
	else
		snprintf(buf, bufsz, "wlan%d-va%d", idx, subidx);

	return buf;
}

int u8_tr069_STRLEN(char *s)
{
	int count = 0;
	int i = 0;

	while (1) {
		u_int32_t test = u8_nextchar(s, &i);

		if (test > 128)
			count += 2;
		else if (test > 0)
			count++;
		else
			break;
	}

	return count;
}

//APACRTL-506
int get_lan_port_num_from_idx(int idx)
{
	/*
	 * GAPD-7100 :
		 idx 0-3 : LAN1 - LAN4
		phyconfig (0 ~ 3) reset;
	 */
	if (idx > MAX_LAN_PORT || idx < 1)
		return -1;

	return (idx - 1);
}

/*-----------------------------------------------------------------------------
 *  mac convert functions
 *-----------------------------------------------------------------------------*/
char *conv_mac_format(char *mac)
{
	unsigned char e[6];

	if (ether_atoe(mac, e)) {
		snprintf(mac, 15, "%02x%02x.%02x%02x.%02x%02x", e[0], e[1], e[2], e[3], e[4], e[5]);
	} else {
		mac[0] = 0;
	}
	return (mac);
}

int conv_mac_format_4_to_a(char *src, char *dst)
{
	unsigned int e1, e2, e3;

	if (sscanf(src, "%x.%x.%x", &e1, &e2, &e3) == 3) {
		snprintf(dst, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		         (e1 >> 8) & 0xff, e1 & 0xff,
		         (e2 >> 8) & 0xff, e2 & 0xff,
		         (e3 >> 8) & 0xff, e3 & 0xff);
		return 0;
	}

	strncpy(dst, "00:00:00:00:00:00", STRLEN("00:00:00:00:00:00"));
	dst[STRLEN("00:00:00:00:00:00")] = 0;
	return -1;
}

int conv_mac_format_4_to_e(char *src, unsigned char e[6])
{
	unsigned int x[3];
	int i;

	if (sscanf(src, "%x.%x.%x", &x[0], &x[1], &x[2]) == 3) {
		for (i = 0; i < 3; i++) {
			e[2 * i] = (unsigned char)((x[i] >> 8) & 0xff);
			e[2 * i + 1] = (unsigned char)(x[i] & 0xff);
		}
		return 0;
	}
	memset(e, 0, 6);
	return (-1);
}

char *conv_mac_format_to_4(char *mac)
{
	unsigned char e[6];

	if (ether_atoe(mac, e)) {
		snprintf(mac, 15, "%02x%02x.%02x%02x.%02x%02x", e[0], e[1], e[2], e[3], e[4], e[5]);
	} else {
		mac[0] = 0;
	}
	return (mac);
}

void remove_colon_from_macaddr(char* dest, char *src, int bufsz, int _case)
{
	char *cp = NULL;
	char mac[32] = {0, };
	int  i = 0;
	int mac_len = 0;

	//source 00:00:00:00:00:00
	//       0123456789abcdef
	memcpy(&mac[0], &src[0], 2);
	src += 2;
	for (i = 1; i < 6; i++) {
		cp = strchr(src, ':');
		if (cp == NULL)
			break;
		src = cp + 1;
		memcpy(&mac[2 * i], src, 2);
	}

	mac_len = STRLEN(mac);

	if (bufsz <= mac_len)
		mac_len = bufsz;

	if (_case == UPPER) {
		for (i = 0; i < mac_len; i++)
			dest[i] = toupper((unsigned char)mac[i]);
	} else {
		for (i = 0; i < mac_len; i++)
			dest[i] = tolower((unsigned char)mac[i]);
	}

	dest[mac_len] = '\0';
}

void add_colon_to_macaddr(char* dest, char *src, int bufsz, int _case)
{
	char mac[32] = {0, };
	int  i = 0, j = 0;
	int mac_len = 0;

	for (i = 0; i < sizeof(mac); i++) {
		if (j > 11)
			break;

		if ((i > 0) && ((i + 1) % 3 == 0)) {
			mac[i] = ':';
		} else {
			mac[i] = src[j++];
		}
	}

	mac_len = STRLEN(mac);

	if (mac_len > 0) {
		if (bufsz <= mac_len)
			mac_len = bufsz;

		if (_case == UPPER) {
			for (i = 0; i < mac_len; i++)
				dest[i] = toupper((unsigned char)mac[i]);
		} else
			strncpy(dest, mac, mac_len);
	}

	dest[mac_len] = '\0';
}

int check_dotted_mac(char *src)
{
	int i;

	if (src == NULL || STRLEN(src) < 14)
		return 0;

	for (i = 0; i < 14; i++) {
		if ((i + 1) % 5 == 0) {
			if (src[i] != '.')
				return 0;
		} else {
			if (!ishex_char(src[i]))
				return 0;
		}
	}

	return 1;
}

int check_colon_mac(char *src)
{
	int i;

	if (src == NULL || STRLEN(src) < 17)
		return 0;

	for (i = 0; i < 17; i++) {
		if ((i + 1) % 3 == 0) {
			if (src[i] != ':')
				return 0;
		} else {
			if (!ishex_char(src[i]))
				return 0;
		}
	}

	return 1;
}

int check_number_mac(char *src)
{
	int i;

	if (src == NULL || STRLEN(src) < 12) {
		return 0;
	}

	for (i = 0; i < 12; i++)
		if (!ishex_char(src[i]))
			return 0;

	return 1;
}

/*-----------------------------------------------------------------------------
 *  API functions
 *-----------------------------------------------------------------------------*/
void init_post_mo_setting(void)
{
	memset(&wanconfig, 0, sizeof(struct wanconfig_t));
	memset(&lanconfig, 0, sizeof(struct lanconfig_t));
}

int get_device_log_from_file(const char *filename, char *log)
{
	FILE *fp = NULL;

	int i = 0;
	long fsize = 0;
	long offset = 0;
	long read_size = LOG_MAXSIZE;
	char text_buf[LOG_MAXSIZE] = {0, };

	fp = fopen(filename, "r");
	if (!fp) {
		printf("fopen() error\n");
		return -1;
	}

	if (fseek(fp, 0, SEEK_END) < 0) {
		printf("fseek() error\n");
		fclose(fp);
		return -1;
	}

	fsize = ftell(fp);
	if (fsize < 0) {
		printf("ftell() error\n");
		fclose(fp);
		return -1;
	}

	rewind(fp);

	if (read_size >= fsize) {
		read_size = fsize;
	} else {
		if (fseek(fp, 0 - read_size, SEEK_END) < 0) {
			printf("fseek() error\n");
			fclose(fp);
			return -1;
		}
	}

	offset = fread((void *)&text_buf[0], 1, read_size, fp);
	if (offset != read_size) {
		printf("fread() error(read_size < fsize)\n");
		fclose(fp);
		return -1;
	}

	while (1) {
		if (text_buf[i++] == '|')
			break;
	}

	memcpy((void *)&log[0], (void *)&text_buf[i], offset - i);

	fclose(fp);

	return 0;
}

void get_producer(char *val, int bufsz, int idx, int subidx)
{
	snprintf(val, bufsz, "%s", "davolink");
}

void get_vendor(char *val, int bufsz, int idx, int subidx)
{
	snprintf(val, bufsz, "%s", "davolink");
}

void get_model(char *val, int bufsz, int is_upper)
{
	int len = 0;
	char *model_name;

	if (is_upper) {
		model_name = DV_PRODUCT_NAME_UPPERCASE;
		len = STRLEN(DV_PRODUCT_NAME_LOWERCASE);
	} else {
		model_name = DV_PRODUCT_NAME_LOWERCASE;
		len = STRLEN(DV_PRODUCT_NAME_LOWERCASE);
	}

	strncpy(val, model_name, len);
	val[len] = '\0';
}

void get_version(char *val, int bufsz, int idx, int subidx)
{
	FILE *fp = NULL;
	char tmpbuf[16] = {0, };
	int len = 0;

	fp = fopen("/etc/version", "r");
	if (fp) {
		fscanf(fp, "%*s %7s", &tmpbuf[0]);
		fclose(fp);
	} else
		snprintf(tmpbuf, sizeof(tmpbuf), "%s", "1.00.00");

	len = STRLEN(tmpbuf);
	strncpy(val, tmpbuf, len);
	val[len] = '\0';
}

int get_port_map_count(void)
{
	int num;
	char *ptr, t[128] = {0, };
	char key[32] = {0, };

	for (num = 0; num < 32;) {
		snprintf(key, sizeof(key), "acs_forward_port%d", num);
		ptr = nvram_safe_get_r(key, t, sizeof(t));
		if (*ptr)
			num++;
		else
			break;
	}
	return num;
}

char *get_clone_macaddr(char *val, int bufsz, int _case)
{
	char tmp[32] = {0, };

	if (!val)
		return NULL;

	nvram_safe_get_r("WAN_MAC_ADDR", tmp, sizeof(tmp));

	add_colon_to_macaddr(val, tmp, bufsz, _case);

	return val;
}

void set_clone_macaddr(char *val, int bufsz, int _case)
{
	char tmp[32] = {0, };

	remove_colon_from_macaddr(tmp, val, sizeof(tmp), _case);

	nvram_set("WAN_MAC_ADDR", tmp);
}

void get_wan_macaddr(char *val, int bufsz, int _case)
{
	char tmp[32] = {0, };
	nvram_safe_get_r("HW_NIC1_ADDR", tmp, sizeof(tmp));
	add_colon_to_macaddr(val, tmp, bufsz, _case);
}

void get_serial(char *val, int bufsz)
{
	nvram_safe_get_r("HW_SERIAL_NO", val, bufsz);
	ydespaces(val);
}

static int check_u8_hangul(u_int32_t ucode)
{
	/* Hangul Syllables          : 0xAC00 ~ 0xD7A3
	 * Hangul Compatibility Jamo : 0x3131 ~ 0x3163
	 */
	if (ucode >= 0xAC00 && ucode <= 0xD7A3)
		return 1;

	if (ucode >= 0x3131 && ucode <= 0x3163)
		return 1;

	return 0;
}

static int valid_u8_ap_name(u_int32_t ucode)
{
	/* 0 ~ 9 : 0x30 ~ 0x39
	 * A ~ Z : 0x41 ~ 0x5A
	 * a ~ z : 0x61 ~ 0x7A
	 * '_'   : 0x5F
	 */
	if (ucode >= 0x30 && ucode <= 0x39)
		return 1;

	if (ucode >= 0x41 && ucode <= 0x5A)
		return 1;

	if (ucode >= 0x61 && ucode <= 0x7A)
		return 1;

	if (ucode == 0x5F)
		return 1;

	if (check_u8_hangul(ucode))
		return 2;

	return 0;
}

char *get_ap_name(char *buf, size_t bufsz)
{
	if (!buf || bufsz == 0)
		return NULL;

	buf[0] = 0;
	nvram_safe_get_r("ap_name", buf, bufsz);

	return buf;
}

int set_ap_name(char *val)
{
	int idx = 0;
	int len = 0;
	int char_len = 0;
	u_int32_t ucode = 0;

	while (1) {
		ucode = u8_nextchar(val, &idx);
		char_len = valid_u8_ap_name(ucode);
		if (char_len)
			len += char_len;
		else if (ucode > 0)
			return 0;
		else
			break;
	}

	if (len > 20)
		return 0;

	nvram_set("ap_name", val);

	return 1;
}

char *get_wanip(char *val, size_t valsz)
{
	int fd, res;
	struct ifreq ifr;
	struct in_addr in;

	if (!val || valsz < IP_BUF_LEN)
		return NULL;

	in.s_addr = INADDR_ANY;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return NULL;

	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", get_wan_name());
	if ((res = ioctl(fd, SIOCGIFADDR, &ifr))) {
		close(fd);
		return NULL;
	}

	in = ((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr;
	snprintf(val, valsz, "%s", inet_ntoa(in));
	ydespaces(val);

	//APACRTL-337
	if (!STRLEN(val) || !nv_strcmp(val, "0.0.0.0"))
		return NULL;

	return val;
}

int set_wanip(char *val)
{
	struct in_addr ip;

	if (!val || STRLEN(val) == 0) {
		wanconfig.err++;
		return 0;
	}

	if (strncmp(val, "0.0.0.0", 8) == 0 || strncmp(val, "255.255.255.255", IP_BUF_LEN) == 0) {
		wanconfig.err++;
		return 0;
	}

	if (!inet_aton(val, &ip)) {
		wanconfig.err++;
		return 0;
	}

	snprintf(wanconfig.ip, sizeof(wanconfig.ip), "%s", val);
	wanconfig.set++;

	return 1;
}

char *get_wanmask(char *val, size_t valsz)
{
	int fd, res;
	struct ifreq ifr;
	struct in_addr in;

	if (!val || valsz < IP_BUF_LEN)
		return NULL;

	in.s_addr = INADDR_ANY;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return NULL;

	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", get_wan_name());
	if ((res = ioctl(fd, SIOCGIFNETMASK, &ifr))) {
		close(fd);
		return NULL;
	}

	in = ((struct sockaddr_in *)&(ifr.ifr_netmask))->sin_addr;
	snprintf(val, valsz, "%s", inet_ntoa(in));
	ydespaces(val);

	if (!STRLEN(val) || !nv_strcmp(val, "0.0.0.0"))
		return NULL;

	return val;
}

int set_wanmask(char *val)
{
	if (!val || STRLEN(val) == 0) {
		wanconfig.err++;
		return 0;
	}

	if (!is_valid_netmask(val)) {
		wanconfig.err++;
		return 0;
	}

	snprintf(wanconfig.nm, sizeof(wanconfig.nm), "%s", val);
	wanconfig.set++;

	return 1;
}

char *get_gateway(char *val, size_t valsz)
{
	FILE *fp = NULL;
	struct in_addr in;
	char str[256] = {0, };
	char *gwname = NULL;
	char *dest = NULL;
	char *ptr;

	if (!val || valsz < IP_BUF_LEN)
		return NULL;

	fp = fopen("/proc/net/route", "r");
	if (!fp)
		return NULL;

	while (fgets(str, sizeof(str), fp)) {
		if (strstr(str, get_wan_name())) {
			STRTOK_R(str, " \t", &ptr);
			dest = STRTOK_R(NULL, " \t", &ptr);
			if (dest && (!nv_strcmp(dest, "00000000"))) {
				gwname = STRTOK_R(NULL, " \t", &ptr);
				break;
			}
		}
	}
	fclose(fp);

	if (!gwname)
		return NULL;

	in.s_addr = strtoul(gwname, NULL, 16);
	snprintf(val, valsz, "%s", inet_ntoa(in));
	ydespaces(val);

	if (!STRLEN(val) || !nv_strcmp(val, "0.0.0.0"))
		return NULL;

	return val;
}

int set_gateway(char *val)
{
	struct in_addr ip;

	if (!val || STRLEN(val) == 0) {
		wanconfig.err++;
		return 0;
	}

	if (strncmp(val, "0.0.0.0", 8) == 0 || strncmp(val, "255.255.255.255", IP_BUF_LEN) == 0) {
		wanconfig.err++;
		return 0;
	}

	if (!inet_aton(val, &ip)) {
		wanconfig.err++;
		return 0;
	}

	snprintf(wanconfig.gw, sizeof(wanconfig.gw), "%s", val);
	wanconfig.set++;

	return 1;
}

char *get_dns(char *val, int bufsz, int idx, int subidx)
{
	FILE *fp = NULL;
	int i = 0, ret;
	char *option = "nameserver";
	char opStr[16] = {0, };
	char ip[20] = {0, };
	char buf[128] = {0, };

	fp = fopen("/etc/resolv.conf", "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			ret = sscanf(buf, "%15s %19s", opStr, ip);
			if (ret == 2 && !nv_strcmp(opStr, option) && ++i == idx) {
				snprintf(val, bufsz, "%s", ip);
			}
		}
		fclose(fp);
	} else {
		snprintf(val, bufsz, "%s", "0.0.0.0");
	}

	return val;
}

int set_dns(char *val)
{
	struct in_addr ip;
	char *ptr_comma = NULL;
	char *dns[2];
	int ret = 0;
	int i = 0;

	char b_dns1[64] = "";
	char b_dns2[64] = "";
	char a_dns1[64] = "";
	char a_dns2[64] = "";

	unlink("/tmp/.mo_a_dns");
	unlink("/tmp/.mo_b_dns");

	//xxx.xxx.xxx.xxx,xxx.xxx.xxx.xxx (31)
	get_dns(b_dns1, sizeof(b_dns1), 1, 0);
	get_dns(b_dns2, sizeof(b_dns2), 2, 0);
	printf("BEFORE dns1 : %s, dns2 : %s\n", b_dns1, b_dns2);

	ptr_comma = strchr(val, ',');
	if (!ptr_comma) {
		//case1 : not included comma (111.222.111.222)
		if (inet_aton(val, &ip)) {
			nvram_set("DNS1", val);
			snprintf(a_dns1, sizeof(a_dns1), "%s", val);
			snprintf(a_dns2, sizeof(a_dns2), "0.0.0.0");
		} else {
			return -1;
		}
	} else {
		//case2 : included comma (111.222.111.222, 111.222.111.222)
		ret = ystrargs(val, dns, 2, " ,\n\t", 0);

		if (ret != 2)
			return -1;

		for (i = 0; i < ret; i++) {
			if (STRLEN(dns[i]) > 0) {
				memset(&ip, 0, sizeof(struct in_addr));
				if (!inet_aton(dns[i], &ip))
					return -1;
			}
		}

		nvram_set("DNS1", dns[0]);
		nvram_set("DNS2", dns[1]);
		snprintf(a_dns1, sizeof(a_dns1), "%s", dns[0]);
		snprintf(a_dns2, sizeof(a_dns2), "%s", dns[1]);
	}

	printf("AFTER dns1 : %s, dns2 : %s\n", a_dns1, a_dns2);
	yecho("/tmp/.mo_b_dns", "%s/%s", b_dns1, b_dns2);
	yecho("/tmp/.mo_a_dns", "%s/%s", a_dns1, a_dns2);

	nvram_set("DNS_MODE", "1");

	return 0;
}

char *get_lanip(char *val, size_t valsz)
{
	if (!val || valsz < IP_BUF_LEN)
		return NULL;

	if (IS_BRIDGE_MODE)
		return get_wanip(val, valsz);

	nvram_safe_get_r("IP_ADDR", val, valsz);
	ydespaces(val);

	if (STRLEN(val) == 0 || nv_strcmp(val, "0.0.0.0") == 0)
		return NULL;

	return val;
}

int set_lanip(char *val)
{
	struct in_addr ip;

	if (!val || STRLEN(val) == 0) {
		lanconfig.err++;
		return 0;
	}

	if (IS_BRIDGE_MODE)
		return set_wanip(val);

	if (!inet_aton(val, &ip)) {
		lanconfig.err++;
		return 0;
	}

	snprintf(lanconfig.ip, sizeof(lanconfig.ip), "%s", val);
	lanconfig.set++;

	return 1;
}

char *get_lanmask(char *val, size_t valsz)
{
	if (!val || valsz < IP_BUF_LEN)
		return NULL;

	if (IS_BRIDGE_MODE)
		return get_wanmask(val, valsz);

	nvram_safe_get_r("SUBNET_MASK", val, valsz);
	ydespaces(val);

	if (STRLEN(val) == 0 || nv_strcmp(val, "0.0.0.0") == 0)
		return NULL;

	return val;
}

int set_lanmask(char *val)
{
	if (!val || STRLEN(val) == 0) {
		lanconfig.err++;
		return 0;
	}

	if (IS_BRIDGE_MODE)
		return set_wanmask(val);

	if (!is_valid_netmask(val)) {
		lanconfig.err++;
		return 0;
	}

	snprintf(lanconfig.nm, sizeof(lanconfig.nm), "%s", val);
	lanconfig.set++;

	return 1;
}

static int set_lan_info(int *set_nvram)
{
	FILE *fp = NULL;
	char buf[128] = {0, };
	char *args[6];
	int res = 0;
	uint32_t lan_ip = 0;
	uint32_t lan_nm = 0;
	uint32_t lan_zero = 0;
	uint32_t dhcp_start = 0;
	uint32_t dhcp_end = 0;
	uint32_t stb_start = 0;
	uint32_t stb_end = 0;
	uint32_t voip_start = 0;
	uint32_t voip_end = 0;
	uint32_t wan_ip = 0;
	uint32_t wan_nm = 0;
	uint32_t wan_zero = 0;
	char old[32] = {0, };
	*set_nvram = 0;

	if (STRLEN(lanconfig.ip) == 0)
		nvram_safe_get_r("IP_ADDR", lanconfig.ip, sizeof(lanconfig.ip));
	if (!conv_ip_to_host_order(lanconfig.ip, &lan_ip))
		return 0;

	if (STRLEN(lanconfig.nm) == 0)
		nvram_safe_get_r("SUBNET_MASK", lanconfig.nm, sizeof(lanconfig.nm));
	if (!conv_ip_to_host_order(lanconfig.nm, &lan_nm))
		return 0;

	nvram_safe_get_r("DHCP_CLIENT_START", buf, sizeof(buf));
	if (!conv_ip_to_host_order(buf, &dhcp_start))
		return 0;
	nvram_safe_get_r("DHCP_CLIENT_END", buf, sizeof(buf));
	if (!conv_ip_to_host_order(buf, &dhcp_end))
		return 0;

	nvram_safe_get_r("stb_ip_start", buf, sizeof(buf));
	if (!conv_ip_to_host_order(buf, &stb_start))
		return 0;
	nvram_safe_get_r("stb_ip_end", buf, sizeof(buf));
	if (!conv_ip_to_host_order(buf, &stb_end))
		return 0;

	nvram_safe_get_r("voip_ip_start", buf, sizeof(buf));
	if (!conv_ip_to_host_order(buf, &voip_start))
		return 0;
	nvram_safe_get_r("voip_ip_end", buf, sizeof(buf));
	if (!conv_ip_to_host_order(buf, &voip_end))
		return 0;

	lan_zero = lan_ip;
	lan_zero &= lan_nm;
	if ((lan_ip == lan_zero) || (lan_ip == (lan_ip | ~lan_nm)))
		return 0;

	dhcp_start &= ~lan_nm;
	dhcp_start |= lan_zero;
	dhcp_end &= ~lan_nm;
	dhcp_end |= lan_zero;
	if (dhcp_start > dhcp_end)
		return 0;
	if (lan_ip >= dhcp_start && lan_ip <= dhcp_end)
		return 0;

	stb_start &= ~lan_nm;
	stb_start |= lan_zero;
	stb_end &= ~lan_nm;
	stb_end |= lan_zero;
	if (stb_start > stb_end)
		return 0;
	if (lan_ip >= stb_start && lan_ip <= stb_end)
		return 0;

	voip_start &= ~lan_nm;
	voip_start |= lan_zero;
	voip_end &= ~lan_nm;
	voip_end |= lan_zero;
	if (voip_start > voip_end)
		return 0;
	if (lan_ip >= voip_start && lan_ip <= voip_end)
		return 0;

	fp = fopen("/proc/net/arp", "r");
	if (!fp)
		return 0;

	//IP address       HW type     Flags       HW address            Mask     Device
	//192.168.123.100  0x1         0x2         64:e5:99:fb:09:03     *        br0
	while (fgets(buf, sizeof(buf), fp)) {
		ydespaces(buf);
		res = ystrargs(buf, args, _countof(args), " \t\r\n", 0);
		if (res != 6)
			continue;
		if (nv_strcmp(LAN_IFNAME, args[5]) == 0 && nv_strcmp(lanconfig.ip, args[0]) == 0) {
			fclose(fp);
			return 0;
		}
	}
	fclose(fp);

	memset(buf, 0, sizeof(buf));
	if (!get_wanip(buf, sizeof(buf)))
		return 0;
	if (STRLEN(buf) == 0 || nv_strcmp(buf, "0.0.0.0") == 0)
		return 0;
	if (!conv_ip_to_host_order(buf, &wan_ip))
		return 0;

	memset(buf, 0, sizeof(buf));
	if (!get_wanmask(buf, sizeof(buf)))
		return 0;
	if (STRLEN(buf) == 0 || nv_strcmp(buf, "0.0.0.0") == 0)
		return 0;
	if (!conv_ip_to_host_order(buf, &wan_nm))
		return 0;

	wan_zero = wan_ip;
	wan_zero &= wan_nm;
	if ((lan_zero >= wan_zero) &&
	    (lan_zero <= (wan_ip | ~wan_nm)))
		return 0;
	if (((lan_ip | ~lan_nm) >= wan_zero) &&
	    ((lan_ip | ~lan_nm) <= (wan_ip | ~wan_nm)))
		return 0;

	conv_host_order_to_ip(buf, sizeof(buf), lan_ip);
	nvram_safe_get_r("IP_ADDR", old, sizeof(old));
	if (nv_strcmp(buf, old)) {
		nvram_set("IP_ADDR", buf);
		*set_nvram = 1;
	}
	conv_host_order_to_ip(buf, sizeof(buf), lan_nm);
	nvram_safe_get_r("SUBNET_MASK", old, sizeof(old));
	if (nv_strcmp(buf, old)) {
		nvram_set("SUBNET_MASK", buf);
		*set_nvram = 1;
	}

	conv_host_order_to_ip(buf, sizeof(buf), dhcp_start);
	nvram_safe_get_r("DHCP_CLIENT_START", old, sizeof(old));
	if (nv_strcmp(buf, old)) {
		nvram_set("DHCP_CLIENT_START", buf);
		*set_nvram = 1;
	}
	conv_host_order_to_ip(buf, sizeof(buf), dhcp_end);
	nvram_safe_get_r("DHCP_CLIENT_END", old, sizeof(old));
	if (nv_strcmp(buf, old)) {
		nvram_set("DHCP_CLIENT_END", buf);
		*set_nvram = 1;
	}

	conv_host_order_to_ip(buf, sizeof(buf), stb_start);
	nvram_safe_get_r("stb_ip_start", old, sizeof(old));
	if (nv_strcmp(buf, old)) {
		nvram_set("stb_ip_start", buf);
		*set_nvram = 1;
	}
	conv_host_order_to_ip(buf, sizeof(buf), stb_end);
	nvram_safe_get_r("stb_ip_end", old, sizeof(old));
	if (nv_strcmp(buf, old)) {
		nvram_set("stb_ip_end", buf);
		*set_nvram = 1;
	}

	conv_host_order_to_ip(buf, sizeof(buf), voip_start);
	nvram_safe_get_r("voip_ip_start", old, sizeof(old));
	if (nv_strcmp(buf, old)) {
		nvram_set("voip_ip_start", buf);
		*set_nvram = 1;
	}
	conv_host_order_to_ip(buf, sizeof(buf), voip_end);
	nvram_safe_get_r("voip_ip_end", old, sizeof(old));
	if (nv_strcmp(buf, old)) {
		nvram_set("voip_ip_end", buf);
		*set_nvram = 1;
	}

	return 1;
}

int set_lan(void)
{
	int set = -(lanconfig.set);
	int set_nvram = 0;

	if (IS_BRIDGE_MODE || lanconfig.err) {
		memset(&lanconfig, 0, sizeof(struct lanconfig_t));
		return set;
	}

	if (lanconfig.set) {
		if (set_lan_info(&set_nvram)) {
			if (set_nvram) {
				set = 0;
			}
		}
	}

	memset(&lanconfig, 0, sizeof(struct lanconfig_t));
	return set;
}

int get_dhcp(void)
{
	//DHCP mode, 0 - fixed ip, 1 - dhcp client, 2 - dhcp server
	//if (access(BRIDGE_MODE_FILE, F_OK) == 0 || nvram_match_r("lan_proto", "static"))
	if (IS_BRIDGE_MODE || nvram_invmatch_r("DHCP", "2"))
		return 0;

	return 1;
}

int set_dhcp(int res)
{
	//if (access(BRIDGE_MODE_FILE, F_OK) == 0)
	if (IS_BRIDGE_MODE)
		return 0;

	if (res == 0)
		nvram_set("DHCP", "0");
	else if (res == 1)
		nvram_set("DHCP", "2");
	else
		return 0;

	return 1;
}

char *get_wan_proto(char *val, int bufsz, int idx, int subidx)
{
	char buf[32] = {0, };
	int wan_proto = 0;

	//stVal = nvram_safe_get_r("wan0_proto", buf, sizeof(buf));
	nvram_safe_get_r("WAN_DHCP", buf, sizeof(buf));
	wan_proto = atoi(buf);

	//protocol, 0 - fixed ip, 1 - dhcp client, 3 - PPPoE, 4 - PPTP, 6 - L2TP
	switch (wan_proto) {
	case 0:
		strncpy(val, "S", 1);
		val[1] = '\0';
		break;

	case 1:
		strncpy(val, "D", 1);
		val[1] = '\0';
		break;

	case 3:
		strncpy(val, "P", 1);
		val[1] = '\0';
		break;

	default:
		val[0] = 0;
		break;
	}				/* -----  end switch  ----- */

	return val;
}

char *get_wan_proto_mo(char *val, size_t valsz)
{
	int wan_proto = 0;
	char proto[16] = {0, };

	if (!val || valsz <= 6)	//max length : 6(Static)
		return val;

	if (IS_BRIDGE_MODE) {
		memset(val, 0, valsz);
		return val;
	}

	nvram_safe_get_r("WAN_DHCP", proto, sizeof(proto));
	wan_proto = atoi(proto);

	//protocol, 0 - fixed ip, 1 - dhcp client, 3 - PPPoE, 4 - PPTP, 6 - L2TP
	switch (wan_proto) {
	case 0:
		snprintf(val, valsz, "Static");
		break;
	case 1:
		snprintf(val, valsz, "DHCP");
		break;
	case 3:
		snprintf(val, valsz, "PPPoE");
		break;
	default:
		memset(val, 0, valsz);
		break;
	}

	return val;
}

int set_wan_proto(char *val)
{
	if (!val || STRLEN(val) == 0) {
		wanconfig.err++;
		return 0;
	}

	if (IS_BRIDGE_MODE)
		return 0;	//do not set wanconfig.set wanconfig.err

	wanconfig.mode = WAN_NOT_SET;
	if (strncmp(val, "DHCP", 5) == 0) {
		wanconfig.mode = WAN_DHCP;
		wanconfig.set++;
	} else if (strncmp(val, "Static", 7) == 0) {
		wanconfig.mode = WAN_STATIC;
		wanconfig.set++;
	} else {
		wanconfig.err++;
		return 0;
	}

	return 1;
}

static int is_wan_static(void)
{
	int ret = 0;
	char mode[8] = {0, };

	nvram_safe_get_r("WAN_DHCP", mode, sizeof(mode));
	if (wanconfig.mode == WAN_STATIC ||
	    (wanconfig.mode == WAN_NOT_SET &&
	     strncmp(mode, NVRAM_STATIC_STR, STRLEN(NVRAM_STATIC_STR) + 1) == 0))
		ret = 1;

	return ret;

}

static int set_wan_info(int *set_nvram)
{
	uint32_t wan_ip = 0;
	uint32_t wan_nm = 0;
	uint32_t wan_gw = 0;
	char buf[32] = {0, };
	char old[32] = {0, };
	FILE *fp = NULL;
	char str[256] = {0, };
	char dns1[32] = {0, };
	char dns2[32] = {0, };

	*set_nvram = 0;

	if (STRLEN(wanconfig.ip) == 0)
		if (!get_wanip(wanconfig.ip, sizeof(wanconfig.ip)))
			return 0;
	if (STRLEN(wanconfig.nm) == 0)
		if (!get_wanmask(wanconfig.nm, sizeof(wanconfig.nm)))
			return 0;
	if (STRLEN(wanconfig.gw) == 0)
		if (!get_gateway(wanconfig.gw, sizeof(wanconfig.gw)))
			return 0;

	if (!conv_ip_to_host_order(wanconfig.ip, &wan_ip))
		return 0;
	if (!conv_ip_to_host_order(wanconfig.nm, &wan_nm))
		return 0;
	if (!conv_ip_to_host_order(wanconfig.gw, &wan_gw))
		return 0;

	if (wan_ip == wan_gw)
		return 0;
	if ((wan_ip & wan_nm) != (wan_gw & wan_nm))
		return 0;
	if ((wan_ip == (wan_gw & wan_nm)) || (wan_ip == (wan_gw | ~wan_nm)))
		return 0;

	if (is_wan_static()) {
		conv_host_order_to_ip(buf, sizeof(buf), wan_ip);
		nvram_safe_get_r("WAN_IP_ADDR", old, sizeof(old));
		if (nv_strcmp(buf, old)) {
			nvram_set("WAN_IP_ADDR", buf);
			*set_nvram = 1;
		}

		conv_host_order_to_ip(buf, sizeof(buf), wan_nm);
		nvram_safe_get_r("WAN_SUBNET_MASK", old, sizeof(old));
		if (nv_strcmp(buf, old)) {
			nvram_set("WAN_SUBNET_MASK", buf);
			*set_nvram = 1;
		}

		conv_host_order_to_ip(buf, sizeof(buf), wan_gw);
		nvram_safe_get_r("WAN_DEFAULT_GATEWAY", old, sizeof(old));
		if (nv_strcmp(buf, old)) {
			nvram_set("WAN_DEFAULT_GATEWAY", buf);
			*set_nvram = 1;
		}
	}

	if (wanconfig.mode == WAN_DHCP) {
		nvram_safe_get_r("WAN_DHCP", old, sizeof(old));
		if (nv_strcmp(NVRAM_DHCP_STR, old)) {
			nvram_set("WAN_DHCP", NVRAM_DHCP_STR);
			*set_nvram = 1;
		}
	} else if (wanconfig.mode == WAN_STATIC) {
		nvram_safe_get_r("WAN_DHCP", old, sizeof(old));
		if (nv_strcmp(NVRAM_STATIC_STR, old)) {
			nvram_set("WAN_DHCP", NVRAM_STATIC_STR);
			*set_nvram = 1;
		}

		fp = fopen("/etc/resolv.conf", "r");
		if (fp) {
			while (fgets(str, sizeof(str), fp)) {
				if (strstr(str, "nameserver ")) {
					if (STRLEN(dns1) < 1) {
						snprintf(dns1, sizeof(dns1), "%s", &str[STRLEN("nameserver ")]);
						ydespaces(dns1);
						continue;
					}

					if (STRLEN(dns2) < 1) {
						snprintf(dns2, sizeof(dns2), "%s", &str[STRLEN("nameserver ")]);
						ydespaces(dns2);
						break;
					}
				}
			}

			fclose(fp);

			if (STRLEN(dns1) > 0) {
				nvram_set("DNS_MODE", "1");
				nvram_set("DNS1", dns1);

				if (STRLEN(dns2) > 0)
					nvram_set("DNS2", dns2);

				*set_nvram = 1;
			}
		}
	}

	return 1;
}

int set_wan(void)
{
	int set = -(wanconfig.set);
	int set_nvram = 0;

	if (!wanconfig.set) {
		memset(&wanconfig, 0, sizeof(struct wanconfig_t));
		return WAN_MO_NOT_SET;
	}

	if (wanconfig.err) {
		memset(&wanconfig, 0, sizeof(struct wanconfig_t));
		return set;
	}

	if (wanconfig.set) {
		if (set_wan_info(&set_nvram)) {
			if (set_nvram) {
				set = 0;
			}
		}
	}

	memset(&wanconfig, 0, sizeof(struct wanconfig_t));
	return set;
}

//APACRTL-482
int set_ssh_passwd(char *val)
{
	int i = 0, j = 0;
	int len;
	char str[32] = {0, };

	if (STRLEN(val) < 13)
		return 0;

	while (i < STRLEN(val)) {
		if (!((val[i] >= '0' && val[i] <= '9') ||
		      (val[i] >= 'A' && val[i] <= 'Z') ||
		      (val[i] >= 'a' && val[i] <= 'z') ||
		      val[i] == '!' || val[i] == '@' ||
		      val[i] == '#' || val[i] == '$' ||
		      val[i] == '%' || val[i] == '^' ||
		      val[i] == '&' || val[i] == '*' ||
		      val[i] == '(' || val[i] == ')'))
			return 0;

		if (val[i] == '%' && i + 2 <= STRLEN(val)) {
			if (val[i + 1] == '2') {
				if (val[i + 2] == '3') {	//%23 == '#'
					str[j++] = 0x23;
					i += 3;
					continue;
				} else if (val[i + 2] == '4') {	//%24 == '$'
					str[j++] = 0x24;
					i += 3;
					continue;
				} else if (val[i + 2] == '5') {	//%25 == '%'
					str[j++] = 0x25;
					i += 3;
					continue;
				} else if (val[i + 2] == '6') {	//%26 == '&'
					str[j++] = 0x26;
					i += 3;
					continue;
				}
			} else if (val[i + 1] == '4' && val[i + 2] == '0') {	//%40 == '@'
				str[j++] = 0x40;
				i += 3;
				continue;
			} else if (val[i + 1] == '5' && (val[i + 2] == 'e' || val[i + 2] == 'E')) {	//%5e == '^'
				str[j++] = 0x5e;
				i += 3;
				continue;
			}
		}

		str[j++] = val[i++];
	}

	len = STRLEN(str);
	str[len] = '\0';

	if (STRLEN(str) < 13 || STRLEN(str) > 16)
		return 0;

	nvram_set("ssh_passwd", str);
	yexecl(NULL, "set_passwd update");

	return 1;
}

//APACRTL-339
char *get_ntp_server(char *val, int valsz, int idx)
{
	char key[32] = {0, };

	if (!val || valsz < IP_BUF_LEN)
		return NULL;

	snprintf(key, sizeof(key), "NTP_SERVER_IP%d", idx);
	nvram_safe_get_r(key, val, valsz);
	ydespaces(val);

	return val;
}

//APACRTL-339
int set_ntp_server(char *val, int idx)
{
	char key[24] = {0, };

	if (!val)
		return 0;

	//val : IP or Domain
	snprintf(key, sizeof(key), "NTP_SERVER_IP%d", idx);
	nvram_set(key, val);

	return 0;
}

char *get_ntp_protocol(char *val, int bufsz, int idx, int subidx)
{
	char buf[16] = {0, };
	char key[16] = {0, };
	int len = 0;

	if (val == NULL)
		return NULL;

	snprintf(key, sizeof(key), "ntp_server_protocol%d", idx);

	nvram_safe_get_r(key, buf, sizeof(buf));
	len = STRLEN(buf);

	if (bufsz <= len) {
		len = bufsz - 1;
		strncpy(val, buf, len);
	} else if (len > 0)
		strncpy(val, buf, len);

	val[len] = '\0';

	return val;
}

char *get_ntp_tz(char *val, int valsz)
{
	char key[32] = {0, };

	if (!val)
		return NULL;

	snprintf(key, sizeof(key), "NTP_TIMEZONE");
	nvram_safe_get_r(key, val, valsz);
	ydespaces(val);

	return val;
}

int set_ntp_tz(char *val)
{
	char key[32] = {0, };

	if (!val)
		return 0;

	snprintf(key, sizeof(key), "NTP_TIMEZONE");
	nvram_set(key, val);

	return 0;
}

/* APACRTL-92 smlee  */
#define TMP_ASICCOUNTER "/tmp/tmp_asicCounter"

#if 0
#define PORT_MIB_PAGE		0x20
#define S_TXOCTET_ADDR		0x00
#define S_RXOCTET_ADDR		0x50
#endif

int get_port_traffic(int pn, uint64 *tr, int is_tx)
{
	FILE *fh = NULL;
	char buf[512] = {0, };
	char str_port[10] = {0, };
	unsigned long long bytes = 0, uni = 0, multi = 0, broad = 0;
	unsigned long long tx_b = 0, rx_b = 0, tx_p = 0, rx_p = 0;
	int receive = 0;

	if (access(TMP_ASICCOUNTER, F_OK) == 0)
		unlink(TMP_ASICCOUNTER);

	yexecl(NULL, "cp /proc/asicCounter " TMP_ASICCOUNTER);

	fh = fopen(TMP_ASICCOUNTER, "r");
	if (!fh) {
		return 0;
	}
	//0~3: LAN, 4: WAN
	snprintf(str_port, sizeof(str_port), "%d:", pn);

	while (fgets(buf, sizeof(buf), fh)) {
		if (strstr(buf, str_port) != 0) {
			sscanf(buf, "%*s %llu %llu %llu %llu %*s %*s %*s %*s %*s", &bytes, &uni, &multi, &broad);
			if (receive == 0) {
				rx_b = bytes;
				rx_p = uni + multi + broad;
				receive = 1;
			} else {
				tx_b = bytes;
				tx_p = uni + multi + broad;
				break;
			}
		}
	}
	//snprintf(str_traffic, sizeof(str_traffic), "%llu %llu %llu %llu", tx_p, rx_p, tx_b, rx_b);
	fclose(fh);

	if (is_tx)
		*tr = tx_b;
	else
		*tr = rx_b;

	return 0;
}

int set_ntp_protocol(char *val, int idx, int subidx)
{
	char buf[128] = {0, }, tmp[128] = {0, };
	char key[32] = {0, };
	char *ptr, *old;
	int ii;

	if (STRNCASECMP(val, "ntp") && STRNCASECMP(val, "tp"))
		return 0;
	snprintf(key, sizeof(key), "ntp_server%d", idx + 1);
	old = nvram_safe_get_r(key, buf, sizeof(buf));
	if (*old) {
		ptr = strsep(&old, ",");
		ii = snprintf(tmp, sizeof(tmp), "%s,", ptr);
		strsep(&old, ",");
		snprintf(tmp + ii, sizeof(tmp) - ii, "%s,%s", val, old);
		nvram_set(key, tmp);
	} else {
		return 0;
	}
	return 1;
}

void get_ntp_port(char *val, int bufsz, int idx, int subidx)
{
	char buf[128] = {0, };
	char key[32] = {0, };
	char *ptr, *old;

	*val = 0;
	snprintf(key, sizeof(key), "ntp_server%d", idx + 1);
	old = nvram_safe_get_r(key, buf, sizeof(buf));
	if (*old) {
		strsep(&old, ",");
		ptr = strsep(&old, ",");
		strncpy(val, old, bufsz);
	}
}

int set_ntp_port(char *val, int idx, int subidx)
{
	char buf[128] = {0, }, tmp[128] = {0, };
	char key[32] = {0, };
	char *ptr, *old, *endptr;
	int ii, res;

	res = strtol(val, &endptr, 10);
	if (STRLEN(endptr) > 0 || res <= 0 || res > 65535)
		return 0;
	snprintf(key, sizeof(key), "ntp_server%d", idx + 1);
	old = nvram_safe_get_r(key, buf, sizeof(buf));
	if (*old) {
		ptr = strsep(&old, ",");
		ii = snprintf(tmp, sizeof(tmp), "%s,", ptr);
		ptr = strsep(&old, ",");
		snprintf(tmp + ii, sizeof(tmp) - ii, "%s,%d", ptr, res);
		nvram_set(key, tmp);
	} else {
		return 0;
	}
	return 1;
}

//Maybe used in qmsmon??
char *get_time_svr(char *val, int bufsz, int idx, int subidx)
{
#if defined (__SERVICE_LGU_HOME__)
	snprintf(val, bufsz, "%s", "00");
#else
	char *p, buf[64] = {0, };

	nvram_safe_get_r("ntp_server", buf, sizeof(buf));
	p = strchr(buf, ' ');
	if (p != NULL)
		*p = 0;
	strncpy(val, buf, bufsz);
#endif
	return val;
}

int set_time_svr(char *val, int idx, int subidx)
{
	char buf[128] = {0, };
	char oldVal[128] = {0, }, *ptr;
	int len, count = 0;
	char *tok_ptr = NULL;

	len = snprintf(buf, sizeof(buf), "%s", val);
	nvram_safe_get_r("ntp_server", oldVal, sizeof(oldVal));
	ptr = STRTOK_R(oldVal, " ", &tok_ptr);
	while (ptr != NULL) {
		if (nv_strcmp(val, ptr)) {
			len += snprintf(buf + len, sizeof(buf) - len, " %s", ptr);
			count++;
		}
		if (count > 1)
			break;
		ptr = STRTOK_R(NULL, " ", &tok_ptr);
	}

	nvram_set("ntp_server", buf);

	return 1;
}

char *get_time_ip(char *val, int bufsz, int idx, int subidx)
{
#if defined (__SERVICE_LGU_HOME__)
	snprintf(val, bufsz, "%s", "00");
#else
	char buf[128] = {0, };
	int  i = 0;

	char *def_tod_addr = "203.252.0.211";
	int def_tod_addr_len = 13;

	char *p = nvram_get_r("tod_server", buf, sizeof(buf));
	if (p == NULL) {
		strncpy(val, def_tod_addr, def_tod_addr_len);
		val[def_tod_addr_len] = '\0';
	} else {
		i = STRLEN(p);
		strncpy(val, p, i);
		val[i] = '\0';
	}
#endif
	return val;
}

int set_time_ip(char *val, int idx, int subidx)
{
#ifdef __SERVICE_LGU_HOME__
#else
	char *old_val, buf[128] = {0, };

	old_val = nvram_safe_get_r("tod_server", buf, sizeof(buf));
	if (STRLEN(val) <= 0 || inet_addr(val) == INADDR_NONE ||
	    (*old_val == 0 && nv_strcmp(val, "203.252.0.211") == 0))
		return 0;

	if (nv_strcmp(val, old_val) != 0) {
		nvram_set("tod_server", val);
		return 1;
	}
#endif
	return 0;
}

int get_routerqos(void)
{
	//routerqos spec is not exist anymore.
#if 0
	char buf[64] = {0, }, *p = NULL;
	long ret;

	p = nvram_get_r("dacom_qos_policy", buf, sizeof(buf));

	if (p != NULL) {
		ret = strtoul(p, NULL, 10);
		switch (ret) {
#if defined(__COMPANY_LG_DACOM__)
		case (0) :
			ret = 2; // qos disable
			break;
		case (1) :
			ret = 0; // HFC
			break;
		case (2) :
			ret = 1; // xDSL
			break;
		default :
			ret = 0;
			break;
#else
		case (0) :
			ret = 0; // qos disable
			break;
		case (1) :
			ret = 1; // HFC
			break;
		case (2) :
			ret = 1; // xDSL
			break;
		default :
			ret = 0;
			break;
#endif
		}
	} else
		ret = 0;

	return ret;
#else
	return 0;
#endif
}

int set_routerqos(int var)
{
#if 0
	char buf[8] = {0, };
	int n = 0;

	if (var < 0 || var > 2)
		return 0;

	switch (var) {
	case 2:		// disable
		n = 0;
		break;
	case 0:
		n = 1;
		break;
	case 1:
		n = 2;
		break;
	}
	snprintf(buf, sizeof(buf), "%d", n);
	nvram_set("dacom_qos_policy", buf);
#endif
	return 0;
}

int get_qosuplimit(void)
{
	char buf[16] = {0, };

	nvram_safe_get_r("dacom_qos_upload_bw_k", buf, sizeof(buf));
	if (buf[0] != 0)
		return (atoi(buf));
	else
		return 400;
}

int set_qosuplimit(int val)
{
	char buf[8] = {0, };

	if (val < 0)
		return 0;
	snprintf(buf, sizeof(buf), "%d", val);
	nvram_set("dacom_qos_upload_bw_k", buf);
	return 1;
}

unsigned int get_fwd_num(void)
{
	int num;

	if (nvram_match("PORTFW_ENABLED", "0"))
		return 0;

	num = nvram_atoi("PORTFW_TBL_NUM", 0);
	return num;
}

void get_fwd_list(struct _port_map_t *List)
{
	char key[64] = {0, };
	char tmpBuf[128] = {0, };
	char *args[8];
	int num, narg;
	int i, j;

	if (nvram_match("PORTFW_ENABLED", "0"))
		return;

	num = nvram_atoi("PORTFW_TBL_NUM", 0);

	if (num > 32)
		num = 32;	// List max size is 32

	for (i = 0, j = 1; j <= num; j++) {
		snprintf(key, sizeof(key), "PORTFW_TBL%d", j);
		nvram_safe_get_r(key, tmpBuf, sizeof(tmpBuf));
		narg = ystrargs(tmpBuf, args, 8, " ,|", 0);
		if (narg != 6)
			continue;

		// args[0] : int_ip
		// args[1] : ext_port_start
		// args[2] : ext_port_end
		// args[3] : prot, 1-tcp, 2-udp, 3-all
		// args[4] : int_port
		// args[5] : enable 1-en, 0-dis
		strncpy(List[i].srcip, args[0], sizeof(List[i].srcip) - 1);
		List[i].srcip[sizeof(List[i].srcip) - 1] = 0;

		List[i].extPort = atoi(args[1]);
		List[i].Range = atoi(args[2]) - List[i].extPort;

		switch (atoi(args[3])) {
		case 1:
			strncpy(List[i].protocol, "TCP", sizeof(List[i].protocol) - 1);
			break;
		case 2:
			strncpy(List[i].protocol, "UDP", sizeof(List[i].protocol) - 1);
			break;
		case 3:
		default:
			strncpy(List[i].protocol, "all", sizeof(List[i].protocol) - 1);
			break;
		}

		List[i].intPort = atoi(args[4]);
		List[i].enable = atoi(args[5]) ? 1 : 0;
		i++;
	}
}

char *get_fwd_list_str(char *val, int bufsz)
{
	char key[64] = {0, };
	char tmpBuf[128] = {0, };
	char *args[8];

	int num, narg;
	int i;
	int len = 0;

	int enable = 0;
	char src_ip[16] = {0, };
	int src_port = 0;
	char dst_port[16] = {0, };
	char proto;

	if (!val)
		return NULL;

	num = nvram_atoi("PORTFW_TBL_NUM", 0);
	if (num > 32)
		num = 32;	// List max size is 32
	else if (num < 1) {
		strncpy(val, "00", 2);
		val[2] = '\0';
		return val;
	}

	for (i = 1; i <= num; i++) {
		snprintf(key, sizeof(key), "PORTFW_TBL%d", i);
		nvram_safe_get_r(key, tmpBuf, sizeof(tmpBuf));
		narg = ystrargs(tmpBuf, args, 8, " ,|", 0);
		if (narg != 6)
			continue;

		// args[0] : int_ip
		// args[1] : ext_port_start
		// args[2] : ext_port_end
		// args[3] : prot, 1-tcp, 2-udp, 3-all
		// args[4] : int_port
		// args[5] : enable 1-en, 0-dis
		snprintf(src_ip, sizeof(src_ip), "%s", args[0]);

		if (atoi(args[1]) == atoi(args[2]))
			if (nv_strcmp(args[1], "0"))
				snprintf(dst_port, sizeof(dst_port), "%s", args[1]);
			else
				snprintf(dst_port, sizeof(dst_port), "%s", "*");
		else
			snprintf(dst_port, sizeof(dst_port), "%s-%s", args[1], args[2]);

		switch (atoi(args[3])) {
		case 1:
			proto = 't';
			break;
		case 2:
			proto = 'u';
			break;
		case 3:
		default:
			proto = '*';
			break;
		}

		src_port = atoi(args[4]);
		enable = atoi(args[5]) ? 1 : 0;

		len += snprintf(val + len, bufsz - len, "%d,%s,%c,%d,%s", enable, src_ip, proto, src_port, dst_port);

		if ((num > 1) && (i < num))
			len += snprintf(val + len, bufsz - len, "%s", "|");
	}

	val[len] = '\0';
	return val;
}

char *get_dmz(char *val, int bufsz, int idx, int subidx)
{
	char buf[16] = {0, };
	int dmz_mode = 0;
	int len = 0;

	if (!val)
		return NULL;

	//check mode (none, dmz, sdmz)
	if (nvram_match_r("DMZ_ENABLED", "1"))
		dmz_mode = 1;
	else if (nvram_match_r("x_sdmz_enable", "1"))
		dmz_mode = 2;

	switch (dmz_mode) {
	//not used
	case 0:
		len = snprintf(val, bufsz, "%s", "0,,");
		break;

	//dmz ip
	case 1:
		if (nvram_safe_get_r("DMZ_HOST", buf, sizeof(buf)) != NULL)
			len = snprintf(val, bufsz, "1,%s,", buf);
		else
			len = snprintf(val, bufsz, "%s", "1,,");
		break;

	//sdmz mac addr
	case 2:
		if (nvram_safe_get_r("x_sdmz_host", buf, sizeof(buf)) != NULL)
			len = snprintf(val, bufsz, "2,,%s", conv_mac_format(buf));
		else
			len = snprintf(val, bufsz, "%s", "2,,");
		break;

	default:
		break;
	}				/* -----  end switch  ----- */

	val[len] = '\0';

	return val;
}

int get_arp_spoofing(char *val)
{
	char *p, buf[4] = {0, };

	if (!val)
		return -1;

	memset(buf, 0, 4);

	if ((p = nvram_get_r("x_ARP_DEFENDER_ENABLE", buf, sizeof(buf))) != NULL) {
		strncpy(val, buf, STRLEN(buf));
		val[STRLEN(buf)] = '\0';
	} else {
		strncpy(val, "0", 1);
		val[1] = '\0';
	}

	return atoi(val);
}

void set_arp_spoofing(int val)
{
	nvram_set("x_ARP_DEFENDER_ENABLE", val ? "1" : "0");
}

static int is_lan_device(const char *strMac)
{
	int port, agingTime;
	char *is_local, *macAddr;
	char *deli = " \t\r\n";
	char temp[128] = {0, }, *ptr;
	FILE *fp;
	int found = 0;
	char *tok_ptr = NULL;

	fp = fopen("/var/tmp/brmac", "r");
	if (fp) {
		while ((found == 0) && ((ptr = fgets(temp, sizeof(temp), fp)) != NULL)) {
			port = atoi(STRTOK_R(ptr, deli, &tok_ptr));
			macAddr = STRTOK_R(NULL, deli, &tok_ptr);
			is_local = STRTOK_R(NULL, deli, &tok_ptr);
			agingTime = atoi(STRTOK_R(NULL, deli, &tok_ptr));
			if (STRNCASECMP(is_local, "no") == 0) {
				if (STRNCASECMP(strMac, macAddr) == 0 && port == 1) {
					found = 1;
					break;
				}
			}
		}
		fclose(fp);
	}
	return found;
}

char *get_static_lease_qms(char *val, int bufsz, int idx, int subidx)
{
	char key[32] = {0, };
	char buf[64] = {0, };
	char mac[16] = {0, };
	char dotted_mac[16] = {0, };
	int i;
	int len = 0;
	int ret;
	char* arg[3];

	if (!val)
		return NULL;

	memset(buf, 0, sizeof(buf));
	nvram_safe_get_r("DHCPRSVDIP_TBL_NUM", buf, sizeof(buf));

	if (atoi(buf) > 0) {
		for (i = 1; i <= 20; i++) {
			memset(buf, 0, sizeof(buf));
			snprintf(key, sizeof(key), "DHCPRSVDIP_TBL%d", i);
			nvram_safe_get_r(key, buf, sizeof(buf));

			//DHCPRSVDIP_TBL2=94fbb2004350,192.168.123.188,1
			ret = ystrargs(buf, arg, 3, ",", 1);
			if (ret != 3)
				continue;

			if (arg[0] != 0) {
				strncpy(mac, arg[0], 12);
				mac[12] = '\0';
				add_colon_to_macaddr(dotted_mac, mac, sizeof(buf), UPPER);
				conv_mac_format(dotted_mac);
			}

			if (arg[0] && arg[1]) {
				if (len == 0)
					len = snprintf(val, bufsz, "%s,%s", arg[1], dotted_mac);
				else
					len += snprintf(val + len, bufsz - len, "|%s,%s", arg[1], dotted_mac);
			}
		}
	} else {
		//if (len == 0)
		snprintf(val, bufsz, "%s", "D");
	}

	return val;
}

#define MAX_IP_TBL		1024
static void add_lease_tbl(struct ip_tbl_t *ip_tbl, int *cnt, char *buf)
{
	char strMac[20] = {0, }, strMask[8] = {0, }, strDev[8] = {0, };
	char strIp[20] = {0, };
	char wanmac[20] = {0, };
	int hwtype, flags;
	int i, found = 0;

	if (strncasecmp(buf, "IP address", STRLEN("IP address")) == 0)
		return;
	if (sscanf(buf, "%19s %x %x %19s %7s %7s", strIp, &hwtype, &flags, strMac, strMask, strDev) != 6 ||
	    STRNCASECMP(strDev, "br0"))
		return;
	get_wan_macaddr(wanmac, sizeof(wanmac), LOWER);
	if (!strncasecmp(strMac, wanmac, 14))
		return;
	for (i = 0; i < *cnt; i++) {
		if (STRNCASECMP(ip_tbl[i].strmac, strMac) == 0) {
			found = 1;
			break;
		}
	}
	if (found == 0 && *cnt < MAX_IP_TBL) {
		snprintf(ip_tbl[*cnt].strip, sizeof(ip_tbl[*cnt].strip), "%s", strIp);
		snprintf(ip_tbl[*cnt].strmac, sizeof(ip_tbl[*cnt].strmac), "%s", strMac);
		*cnt += 1;
	}
}

int get_device_info(struct ip_tbl_t *List)
{
	char *argv[] = { "brctl", "showmacs", "br0", NULL };
	char *argv1[] = { "killall", "-SIGUSR1", "udhcpd", NULL };
	FILE *fp = NULL;
	char temp[128] = {0, };
	int len = 0;
	struct lease_t lease = { };
	struct ip_tbl_t ip_tbl[MAX_IP_TBL], *info;
	int i, cnt = 0;
	int expires;

#if defined (__LGU_5000H__) || defined (__SERVICE_LGU_ENT__)
	if (nvram_match_r("hub_port_disable", "0") || idx > 1) {
		snprintf(val, bufsz, "%s", "00");
		return;
	}
#endif

	memset(ip_tbl, 0, sizeof(struct ip_tbl_t) * MAX_IP_TBL);
	if (!IS_BRIDGE_MODE) {
		yexecv(argv1, NULL, 5, NULL);
		fp = fopen(DHCPD_LEASE_FILE, "r");
		if (fp) {
			while (fread(&lease, sizeof(lease), 1, fp)) {
				if (cnt >= MAX_IP_TBL)
					break;
				if (ETHER_ISNULLADDR(lease.chaddr))
					continue;
				expires = ntohl(lease.expires);
				if (expires == 0)
					continue;

				struct in_addr in;
				in.s_addr = lease.yiaddr;
				snprintf(ip_tbl[cnt].strip, sizeof(ip_tbl[cnt].strip),
				         "%s", inet_ntoa(in));

				snprintf(ip_tbl[cnt].strmac, sizeof(ip_tbl[cnt].strmac),
				         "%02x:%02x:%02x:%02x:%02x:%02x",
				         lease.chaddr[0], lease.chaddr[1], lease.chaddr[2],
				         lease.chaddr[3], lease.chaddr[4], lease.chaddr[5]);
				ip_tbl[cnt].expires = expires;
				cnt += 1;
			}
			fclose(fp);
			unlink(DHCPD_LEASE_FILE);
		}
	}
	if ((fp = fopen("/proc/net/arp", "r")) != NULL) {
		while (fgets(temp, sizeof(temp), fp) != NULL)
			add_lease_tbl(ip_tbl, &cnt, temp);
		fclose(fp);
	}
	yexecv(argv, ">/var/tmp/brmac", 5, NULL);
	info = List;
	for (i = 0; i < cnt; i++) {
		if (is_lan_device(ip_tbl[i].strmac)) {
			snprintf(info->strip, sizeof(info->strip), "%s", ip_tbl[i].strip);
			snprintf(info->strmac, sizeof(info->strmac), "%s", ip_tbl[i].strmac);
			info->expires = ip_tbl[i].expires;
			info++;
			len++;
		}
	}
	unlink("/var/tmp/brmac");

	return len;
}

int get_connected_port_with_mac(char *mac)
{
	FILE *fp = NULL;
	char temp[128] = {0, };

	char tmp_mac[20] = {0, };
	char mbr_line[32] = {0, };
	int port;

	char *ptr = NULL;

	fp = fopen("/proc/rtl865x/l2", "r");
	if (fp) {
		//ignore first line
		fgets(temp, sizeof(temp), fp);

		//31.[126,0] f8:bc:12:73:00:5b FID:0 mbr(0 )FWD DYN   age:450 AUTH:0
		//8.[ 15,0] ff:ff:ff:ff:ff:ff FID:1 mbr(0 1 2 3 4 8 )CPU STA  NH age:0 AUTH:1
		while (fgets(temp, sizeof(temp), fp) != NULL) {
			ptr = strchr(temp, ']');
			if (!ptr)
				continue;

			ptr += 2;

			sscanf(ptr, "%19s %*s %31s", tmp_mac, mbr_line);
			if (!nv_strcmp(mac, tmp_mac)) {
				//parsing mbr line
				port = atoi(&mbr_line[4]);
				if (port < 0 && port > 3)
					continue;
				fclose(fp);
				return (port + 1);
			}

		}

		fclose(fp);
	}

	return -1;
}

char *get_lanport_device_mac(char *val, int bufsz, int idx)
{
	int len = 0;
	int cnt = 0;
	int i = 0;
	int pn = 0;
	struct ip_tbl_t ip_tbl[MAX_IP_TBL];
	/*
		if (IS_BRIDGE_MODE) {
			strncpy(val, "00", 2);
			val[2] = '\0';
			return val;
		}
	*/

	memset(ip_tbl, 0, sizeof(struct ip_tbl_t) * MAX_IP_TBL);

	cnt = get_device_info(ip_tbl);

	for (i = 0; i < cnt; i++) {
		//1. mac은 어느 포트에 접속되어 있나?
		pn = get_connected_port_with_mac(ip_tbl[i].strmac);

		//2. 만약 idx와 접속된 포트가 같으면 mac을 출력한다.
		if (pn == idx) {
			len += snprintf(val + len, bufsz - len, "%s", conv_mac_format(ip_tbl[i].strmac));

			if ((cnt > 1) && (i < cnt - 1))
				len += snprintf(val + len, bufsz - len, "%s", "|");
		}
	}

	val[len] = '\0';

	return val;
}



char *get_lanport_device_ip(char *val, int bufsz, int idx)
{
	int len = 0;
	int cnt = 0;
	int i = 0;
	int pn = 0;
	struct ip_tbl_t ip_tbl[MAX_IP_TBL];

	memset(ip_tbl, 0, sizeof(struct ip_tbl_t) * MAX_IP_TBL);

	cnt = get_device_info(ip_tbl);

	for (i = 0; i < cnt; i++) {
		//1. mac은 어느 포트에 접속되어 있나?
		pn = get_connected_port_with_mac(ip_tbl[i].strmac);

		//2. 만약 idx와 접속된 포트가 같으면 ip를 출력한다.
		if (pn == idx) {
			len += snprintf(val + len, bufsz - len, "%s", ip_tbl[i].strip);

			if ((cnt > 1) && (i < cnt - 1))
				len += snprintf(val + len, bufsz - len, "%s", "|");
		}
	}

	val[len] = '\0';

	return val;
}

#define _PATH_PROCNET_DEV	"/proc/net/dev"

/* type define */
struct user_net_device_stats {
	unsigned long long rx_packets;	/* total packets received        */
	unsigned long long tx_packets;	/* total packets transmitted     */
	unsigned long long rx_bytes;	/* total bytes received          */
	unsigned long long tx_bytes;	/* total bytes transmitted       */
	unsigned long rx_errors;		/* bad packets received          */
	unsigned long tx_errors;		/* packet transmit problems      */
	unsigned long rx_dropped;		/* no space in linux buffers     */
	unsigned long tx_dropped;		/* no space available in linux   */
	unsigned long rx_multicast;		/* multicast packets received    */
	unsigned long tx_multicast;		/* multicast packets transmitted */
	unsigned long rx_unicast;		/* unicast packets received      */
	unsigned long tx_unicast;		/* unicast packets transmitted   */
	unsigned long rx_broadcast;		/* broadcast packets received    */
	unsigned long tx_broadcast;		/* broadcast packets transmitted */
	unsigned long rx_compressed;
	unsigned long tx_compressed;
	unsigned long collisions;

	/* detailed rx_errors: */
	unsigned long rx_length_errors;
	unsigned long rx_over_errors;	/* receiver ring buff overflow  */
	unsigned long rx_crc_errors;	/* recved pkt with crc error    */
	unsigned long rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long rx_fifo_errors;	/* recv'r fifo overrun          */
	unsigned long rx_missed_errors;	/* receiver missed packet       */

	/* detailed tx_errors */
	unsigned long tx_aborted_errors;
	unsigned long tx_carrier_errors;
	unsigned long tx_fifo_errors;
	unsigned long tx_heartbeat_errors;
	unsigned long tx_window_errors;
};


/////////////////////////////////////////////////////////////////////////////
static char *get_name(char *name, char *p)
{
	while (isspace(*p))
		p++;
	while (*p) {
		if (isspace(*p))
			break;
		if (*p == ':') {	/* could be an alias */
			char *dot = p, *dotname = name;
			*name++ = *p++;
			while (isdigit(*p))
				*name++ = *p++;
			if (*p != ':') {	/* it wasn't, backup */
				p = dot;
				name = dotname;
			}
			if (*p == '\0')
				return NULL;
			p++;
			break;
		}
		*name++ = *p++;
	}
	*name++ = '\0';
	return p;
}

////////////////////////////////////////////////////////////////////////////////
static int get_dev_fields(int type, char *bp, struct user_net_device_stats *pStats)
{
	switch (type) {
	case 3:
		sscanf(bp,
		       "%llu %llu %lu %lu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu %lu",
		       &pStats->rx_bytes,
		       &pStats->rx_packets,
		       &pStats->rx_errors,
		       &pStats->rx_dropped,
		       &pStats->rx_fifo_errors,
		       &pStats->rx_frame_errors,
		       &pStats->rx_compressed,
		       &pStats->rx_multicast,

		       &pStats->tx_bytes,
		       &pStats->tx_packets,
		       &pStats->tx_errors,
		       &pStats->tx_dropped,
		       &pStats->tx_fifo_errors,
		       &pStats->collisions,
		       &pStats->tx_carrier_errors,
		       &pStats->tx_compressed);
		break;

	case 2:
		sscanf(bp, "%llu %llu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu",
		       &pStats->rx_bytes,
		       &pStats->rx_packets,
		       &pStats->rx_errors,
		       &pStats->rx_dropped,
		       &pStats->rx_fifo_errors,
		       &pStats->rx_frame_errors,

		       &pStats->tx_bytes,
		       &pStats->tx_packets,
		       &pStats->tx_errors,
		       &pStats->tx_dropped,
		       &pStats->tx_fifo_errors,
		       &pStats->collisions,
		       &pStats->tx_carrier_errors);
		pStats->rx_multicast = 0;
		break;

	case 1:
		sscanf(bp, "%llu %lu %lu %lu %lu %llu %lu %lu %lu %lu %lu",
		       &pStats->rx_packets,
		       &pStats->rx_errors,
		       &pStats->rx_dropped,
		       &pStats->rx_fifo_errors,
		       &pStats->rx_frame_errors,

		       &pStats->tx_packets,
		       &pStats->tx_errors,
		       &pStats->tx_dropped,
		       &pStats->tx_fifo_errors,
		       &pStats->collisions,
		       &pStats->tx_carrier_errors);
		pStats->rx_bytes = 0;
		pStats->tx_bytes = 0;
		pStats->rx_multicast = 0;
		break;
	}
	return 0;
}

/////////////////////////////////////////////////////////////////////////////
int getStats(char *interface, struct user_net_device_stats *pStats)
{
	FILE *fh = NULL;
	char buf[512] = {0, };
	int type;

	fh = fopen(_PATH_PROCNET_DEV, "r");
	if (!fh) {
		printf("Warning: cannot open %s\n", _PATH_PROCNET_DEV);
		return -1;
	}
	fgets(buf, sizeof buf, fh);	/* eat line */
	fgets(buf, sizeof buf, fh);

	if (strstr(buf, "compressed"))
		type = 3;
	else if (strstr(buf, "bytes"))
		type = 2;
	else
		type = 1;

	while (fgets(buf, sizeof buf, fh)) {
		char *s, name[40] = {0, };
		s = get_name(name, buf);
		if (nv_strcmp(interface, name))
			continue;
		get_dev_fields(type, s, pStats);
		fclose(fh);
		return 0;
	}
	fclose(fh);
	return -1;
}

uint64 get_dev_stat_info(char *inf, int isTx)
{
	uint64 res = 0;
	struct user_net_device_stats Stats = { };

	if (getStats(inf, &Stats) == 0) {
		if (isTx)
			res = Stats.tx_bytes;
		else
			res = Stats.rx_bytes;
	}

	return res;
#if 0
	char tmp[256] = {0, };
	unsigned int result;
	unsigned int a[8];
	uint64 tx[2], rx[2];
	uint64 res = 0;
	FILE *fp = NULL;
	char *ptr;

	fp = fopen("/proc/dv_dev_stat", "r");
	if (!fp)
		return 0;

	while (fgets(tmp, sizeof(tmp), fp)) {
		ptr = strstr(tmp, inf);
		if (ptr == NULL || STRLEN(ptr) <= STRLEN(inf))
			continue;
		ptr += STRLEN(inf);
		result = sscanf(ptr, "%u %u %u %llu %llu %u %u %u %u %llu %llu %u",
		                &a[0], &a[1], &a[2], &rx[0], &rx[1], &a[3], &a[4], &a[5], &a[6], &tx[0], &tx[1], &a[7]);

		if (result == 12) {
			if (isTx)
				res = tx[0];
			else
				res = rx[0];
			break;
		}
	}
	fclose(fp);
#endif
}

unsigned int get_traffic(char *itf, int search_index)
{
	FILE *fp = NULL;
	int index = -1, i = 0;
	char buf[256] = {0, };
	char *value, *ptr;
	char *tok_ptr = NULL;

	/*---------------------------------------------------------------------------------
	[ search_index ]
		Receive
			1=bytes 2=packets 3=errs 4=drop 5=fifo 6=frame 7=compressed 8=multicast
		Transmit
			9=bytes 10=packets 11=errs 12=drop 13=fifo 14=colls 15=carrier 16=compressed
	---------------------------------------------------------------------------------*/

	fp = fopen("/proc/net/dev", "r");
	if (!fp)
		return 0;

	while (fgets(buf, sizeof(buf), fp)) {
		if (strstr(buf, itf)) {
			index = i;
			break;
		}
		i++;
	}
	fclose(fp);

	if (index < 0)
		return 0;

	ptr = buf;
	value = STRTOK_R(ptr, ":", &tok_ptr);
	if (!value)
		return 0;

	for (i = 0; i < search_index && value; i++)
		value = STRTOK_R(NULL, " \t\n", &tok_ptr);

	if (value)
		return (unsigned int)strtoul(value, NULL, 10);

	return 0;
}

char *get_ssid(char *buf, int bufsz, int idx, int subidx)
{
	char param[32] = {0, };
	char tmp[256] = {0, };
	char enc_msg[1024] = {0, };
	int enc_len = 0;

	if (subidx == -1)
		snprintf(param, sizeof(param), "WLAN%d_SSID", idx);
	else
		snprintf(param, sizeof(param), "WLAN%d_VAP%d_SSID", idx, subidx);

	nvram_safe_get_r(param, tmp, sizeof(tmp));
	enc_len = percent_encode(tmp, enc_msg, sizeof(enc_msg));
	enc_msg[enc_len] = 0;

	snprintf(buf, bufsz, "%s", enc_msg);

	return buf;
}

int set_ssid(char *val, int idx, int subidx)
{
	char param[32] = {0, };

	if (STRLEN(val) == 0)
		return 0;

	if (subidx == -1)
		snprintf(param, sizeof(param), "WLAN%d_SSID", idx);
	else
		snprintf(param, sizeof(param), "WLAN%d_VAP%d_SSID", idx, subidx);

	if (u8_tr069_STRLEN(val) > 32)
		return 0;

	nvram_set(param, val);

	return 1;
}

static int yxatoi(unsigned char *dst, const char *src, int len)
{
	unsigned int val;
	int c, i, ii;

	for (i = 0; i < len; i += 2) {
		for (val = ii = 0; ii < 2; ii++) {
			c = *src++;
			if (isdigit(c))
				val = (val << 4) + (int)(c - '0');
			else if (isxdigit(c))
				val = (val << 4) | (int)(c + 10 - (islower(c) ? 'a' : 'A'));
			else
				return 0;
		}
		*dst++ = val;
	}

	return (*src) ? 0 : 1;
}

char *get_bssid(char *buf, int bufsz, int idx, int subidx)
{
	char param[32] = {0, };
	unsigned char mac[6] = {0, };
	char tmp[20] = {0, };

	snprintf(param, sizeof(param), "HW_WLAN%d_WLAN_ADDR", idx);
	nvram_safe_get_r(param, tmp, sizeof(tmp));
	yxatoi(mac, tmp, sizeof(mac) << 1);

	if (subidx == -1) {
		snprintf(buf, bufsz, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	} else {
		subidx += 1;
		mac[0] = (mac[0] + (subidx << 4)) | 2;
		snprintf(buf, bufsz, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

	return buf;
}

int get_ssid_enable(int idx, int subidx)
{
	char param[32] = {0, };

	if (subidx == -1)
		snprintf(param, sizeof(param), "WLAN%d_FUNC_OFF", idx);
	else
		snprintf(param, sizeof(param), "WLAN%d_VAP%d_WLAN_DISABLED", idx, subidx);

	if (nvram_match_r(param, "0"))
		return 1;
	else
		return 0;
}

int set_ssid_enable(int val, int idx, int subidx)
{
	char param[32] = {0, };

	if (val != 0 && val != 1)
		return 0;

	if (subidx == -1)
		snprintf(param, sizeof(param), "WLAN%d_FUNC_OFF", idx);
	else
		snprintf(param, sizeof(param), "WLAN%d_VAP%d_WLAN_DISABLED", idx, subidx);

	nvram_set(param, val ? "0" : "1");

	return 1;
}

int get_bss_max_assoc(int idx, int subidx)
{
	char param[32] = {0, };
	char temp[4] = {0, };

	if (subidx == -1)
		snprintf(param, sizeof(param), "x_wlan%d_max_conn", idx);
	else
		snprintf(param, sizeof(param), "x_wlan%d_va%d_max_conn", idx, subidx);

	nvram_safe_get_r(param, temp, sizeof(temp));

	return (atoi(temp) == 128 ? 0 : atoi(temp));
}

int set_bss_max_assoc(int res, int idx, int subidx)
{
	char param[32] = {0, };
	char temp[4] = {0, };

	if (res < 0 || res > 127)
		return 0;

	snprintf(temp, sizeof(temp), "%d", res == 0 ? 128 : res);

	if (subidx == -1)
		snprintf(param, sizeof(param), "x_wlan%d_max_conn", idx);
	else
		snprintf(param, sizeof(param), "x_wlan%d_va%d_max_conn", idx, subidx);

	nvram_set(param, temp);

	return 1;
}

//APACRTL-602
#define WLAN_RATELIMIT_TR069 "/tmp/.tr069_rate"

struct wl_ratelimit_t {
	short set_chk;
	short enable;
	int tx_restrict;
	int rx_restrict;
};

static struct wl_ratelimit_t wrt[MAX_WL_INTF][MAX_WL_BSS];

void init_wl_ratelimit_t(void)
{
	memset(&wrt[0][0], -1, sizeof(wrt));
}

void set_wl_rate_limit(void)
{
	char wl_name[16] = "";
	char proc_wlname[128] = "";
	int tx_restrict = 0, rx_restrict = 0;
	int i, j;
	int enabled;

	for (i = 0; i < MAX_WL_INTF; i++) {
		for (j = 0; j < MAX_WL_BSS; j++) {
			if (wrt[i][j].set_chk == 1) {
				if ((enabled = wrt[i][j].enable) == -1)
					enabled = get_traffic_limit_on(i, j - 1);
				else if (i == 0 && j == 0) {
					if (enabled)
						yecho(WLAN_RATELIMIT_TR069, "1");
					else
						unlink(WLAN_RATELIMIT_TR069);
				}

				if ((tx_restrict = wrt[i][j].tx_restrict) == -1)
					tx_restrict = get_traffic_limit_tx(i, j - 1);
				else if ((i == 0 && j == 0) && enabled)
					yecho(WLAN_RATELIMIT_TR069, "1");

				if ((rx_restrict = wrt[i][j].rx_restrict) == -1)
					rx_restrict = get_traffic_limit_rx(i, j - 1);
				else if ((i == 0 && j == 0) && enabled)
					yecho(WLAN_RATELIMIT_TR069, "1");

			} else if ((enabled = get_traffic_limit_on(i, j - 1)) != 0) {
				//check enable from nvram
				tx_restrict = get_traffic_limit_tx(i, j - 1);
				rx_restrict = get_traffic_limit_rx(i, j - 1);
			} else
				continue;

			if (wrt[i][j].set_chk == 1) {
				snprintf(proc_wlname, sizeof(proc_wlname), "/proc/dv_%s/dv_rate_limit", ((i == 0) ? "wlan0" : "wlan1"));
				get_wlan_ifname_from_idx(wl_name, sizeof(wl_name), i, j - 1);
				yfecho(proc_wlname, O_WRONLY | O_CREAT | O_TRUNC, 0644, "clear %s 0 0", wl_name);

				if (enabled) {
					//fprintf(stderr, "(%s) tx restrict : %d - enabled : %d\n", wl_name, tx_restrict, enabled);
					if (tx_restrict > 0) {
						yfecho(proc_wlname, O_WRONLY | O_CREAT | O_TRUNC, 0644, "to wlan0 %dk 50", tx_restrict);
					}

					//fprintf(stderr, "(%s) rx restrict : %d - enabled : %d\n", wl_name, rx_restrict, enabled);
					if (rx_restrict > 0) {
						yfecho(proc_wlname, O_WRONLY | O_CREAT | O_TRUNC, 0644, "from wlan0 %dk 50", rx_restrict);
					}
				}
			}
		}
	}

	init_wl_ratelimit_t();
	return;
}

int get_traffic_limit_on(int idx, int subidx)
{
	char param[32] = {0, }, temp[8] = {0, };

	if (subidx == -1)
		snprintf(param, sizeof(param), "wlan%d_dv_ratelimit_on", idx);
	else
		snprintf(param, sizeof(param), "wlan%d_vap%d_dv_ratelimit_on", idx, subidx);

	return atoi(nvram_safe_get_r(param, temp, sizeof(temp)));
}

int set_traffic_limit_on(int val, int idx, int subidx)
{
	char param[32] = {0, }, buf[4] = {0, };
	struct wl_ratelimit_t *wrt_p = &wrt[idx][subidx + 1];

	if (val != 0 && val != 1)
		return 0;

	wrt_p->set_chk = 1;
	wrt_p->enable = val;

	if (subidx == -1)
		snprintf(param, sizeof(param), "wlan%d_dv_ratelimit_on", idx);
	else
		snprintf(param, sizeof(param), "wlan%d_vap%d_dv_ratelimit_on", idx, subidx);

	snprintf(buf, sizeof(buf), "%d", val);
	nvram_set(param, buf);

	return 1;
}

int get_traffic_limit_tx(int idx, int subidx)
{

	char param[32] = {0, }, temp[8] = {0, };

	if (subidx == -1)
		snprintf(param, sizeof(param), "WLAN%d_TX_RESTRICT", idx);
	else
		snprintf(param, sizeof(param), "WLAN%d_VAP%d_TX_RESTRICT", idx, subidx);

	return (atoi(nvram_safe_get_r(param, temp, sizeof(temp))));
}

int set_traffic_limit_tx(int val, int idx, int subidx)
{
	char param[32] = {0, };
	char buf[32] = {0, };
	struct wl_ratelimit_t *wrt_p = &wrt[idx][subidx + 1];

	if (val < 0)
		return 0;

	wrt_p->set_chk = 1;
	wrt_p->tx_restrict = val;

	if (subidx == -1)
		snprintf(param, sizeof(param), "WLAN%d_TX_RESTRICT", idx);
	else
		snprintf(param, sizeof(param), "WLAN%d_VAP%d_TX_RESTRICT", idx, subidx);

	snprintf(buf, sizeof(buf), "%d", val);
	nvram_set(param, buf);

	return 1;
}

int get_traffic_limit_rx(int idx, int subidx)
{
	char param[32] = {0, }, temp[8] = {0, };

	if (subidx == -1)
		snprintf(param, sizeof(param), "WLAN%d_RX_RESTRICT", idx);
	else
		snprintf(param, sizeof(param), "WLAN%d_VAP%d_RX_RESTRICT", idx, subidx);

	return (atoi(nvram_safe_get_r(param, temp, sizeof(temp))));
}

int set_traffic_limit_rx(int val, int idx, int subidx)
{
	char param[32] = {0, }, temp[8] = {0, };
	struct wl_ratelimit_t *wrt_p = &wrt[idx][subidx + 1];

	if (val < 0)
		return 0;

	wrt_p->set_chk = 1;
	wrt_p->rx_restrict = val;

	if (subidx == -1)
		snprintf(param, sizeof(param), "WLAN%d_RX_RESTRICT", idx);
	else
		snprintf(param, sizeof(param), "WLAN%d_VAP%d_RX_RESTRICT", idx, subidx);

	snprintf(temp, sizeof(temp), "%d", val);
	nvram_set(param, temp);

	return 1;
}

int get_rssi_limit(int idx, int subidx)
{
	char param[32] = {0, };
	char tmp[8] = {0, };
	int val;

	if (subidx == -1)
		snprintf(param, sizeof(param), "x_wlan%d_rssi_threshold", idx);
	else
		snprintf(param, sizeof(param), "x_wlan%d_va%d_rssi_threshold", idx, subidx);

	val = atoi(nvram_safe_get_r(param, tmp, sizeof(tmp)));
	if (val != 0)
		val *= -1;

	return val;
}

int set_rssi_limit(int val, int idx, int subidx)
{
	char param[32] = {0, };
	char tmp[8] = {0, };

	if (val < -100 || val > 0)
		return 0;

	if (subidx == -1)
		snprintf(param, sizeof(param), "x_wlan%d_rssi_threshold", idx);
	else
		snprintf(param, sizeof(param), "x_wlan%d_va%d_rssi_threshold", idx, subidx);

	if (val != 0)
		val *= -1;

	snprintf(tmp, sizeof(tmp), "%d", val);
	nvram_set(param, tmp);

	return 1;
}

static int getWlStaInfo(char *interface, WLAN_STA_INFO_Tp pInfo)
{
	int skfd = 0;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
		return -1;

	wrq.u.data.pointer = (caddr_t)pInfo;
	wrq.u.data.length = sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM + 1);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLSTAINFO, &wrq) < 0) {
		close(skfd);
		return -1;
	}

	close(skfd);
	return 0;
}

static void get_wl_sta_info(WLAN_STA_INFO_Tp pInfo, wl_client_info_t *info)
{
	ether_etoa(pInfo->addr, info->macAddr);

	if (IS_BRIDGE_MODE)
		snprintf(info->ipAddr, sizeof(info->ipAddr), "%s", "0.0.0.0");
	else
		find_ip_with_mac(info->macAddr, info->ipAddr, sizeof(info->ipAddr));

	info->assocTime = time(NULL) - pInfo->link_time;

	info->rssi = CONV_TO_RSSI(pInfo->rssi);

	info->tx_bytes = pInfo->tx_bytes;
	info->rx_bytes = pInfo->rx_bytes;
}

static int get_assoc_client(char *ifname, int lgauth, wl_client_info_t *info)
{
	int i;
	int len = 0;
	char *buff = NULL;
	WLAN_STA_INFO_Tp pInfo;

	buff = calloc(1, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM + 1));
	if (buff == NULL)
		return 0;

	if (getWlStaInfo(ifname, (WLAN_STA_INFO_Tp)buff) == 0) {
		for (i = 1; i < MAX_STA_NUM; i++) {
			pInfo = (WLAN_STA_INFO_Tp)&buff[i * sizeof(WLAN_STA_INFO_T)];
			if (pInfo->aid && (pInfo->flags & STA_INFO_FLAG_ASOC)) {
				get_wl_sta_info(pInfo, info);
				info->auth_info = lgauth; // 1:none, 2:MAC, 3:MD5, 4:MAC+MD5, 5:EAP, 6:WEB, 7:WEB+MAC
				len++;
				info++;
			}
		}
	}

	free(buff);
	return len;
}

static int get_mbr_client_info(char *ifname, int lgauth, wl_client_info_t *info)
{
	int i;
	FILE *fp = NULL;
	char cmd[80] = {0, }, line[256] = {0, };
	int ret = 0;
	char macAddr[ETHER_ADDR_STR_LEN] = {0, };
	int assoc_time, count;
	char auth_type;
	time_t tt;

	ret = get_assoc_client(ifname, lgauth, info);

	if (lgauth < 5) // 1:none, 2:MAC, 3:MD5, 4:MAC+MD5, 5:EAP, 6:WEB, 7:WEB+MAC
		return ret;

	yfecho("/tmp/nas_cmd", O_WRONLY | O_CREAT | O_TRUNC, 0644, "dump %s", ifname);
	yexecl(NULL, "killall -USR1 dv_auth");

	snprintf(cmd, sizeof(cmd), "/tmp/nas_sta_dump_%s", ifname);

	fp = fopen(cmd, "r");
	if (fp == NULL)
		return ret;

// GET RADIUS ASSOC TIME
	while (fgets(line, sizeof(line), fp)) {
		assoc_time = 0;
		count = sscanf(line, "%17s %*s %c %*s %*s %*d %*d %d %*x %*d %*s",
		               macAddr, &auth_type, &assoc_time);

		tt = time(NULL) - assoc_time;
		if (count == 5 && assoc_time > 0) {
			for (i = 0; i < ret; i++) {
				if (!strncasecmp(info[i].macAddr, macAddr, 17)) {
					info[i].assocTime = tt;
					info[i].auth_type = auth_type;
				}
				if (ret > 127)
					break;
			}
		}
	}

	fclose(fp);
	unlink(cmd);

	return ret;
}

int get_wl_client_info(int idx, int subidx)
{
	int ret = 0;
	char wl_name[32] = {0, };
	char nv_name[24] = {0, };
	char tmp[8] = {0, };
	int lgauth;

	get_wlan_ifname_from_idx(wl_name, sizeof(wl_name), idx, subidx);

	if (subidx == -1)
		snprintf(nv_name, sizeof(nv_name), "x_WLAN%d_LGAUTH", idx);
	else
		snprintf(nv_name, sizeof(nv_name), "x_WLAN%d_VAP%d_LGAUTH", idx, subidx);

	lgauth = atoi(nvram_get_r_def(nv_name, tmp, sizeof(tmp), "0")) + 1;

	memset(info, 0, sizeof(wl_client_info_t) * 128);
	ret = get_mbr_client_info(wl_name, lgauth, info);

	return ret;
}

static char *ssid_name[2][7] = {
	{
		//"vssid",  //voice ssid is not applied in GAPD-7100
		"datassid",
		"mssid",
		"rssid",
		"r2ssid",
		"r3ssid",
		"r4ssid",
		"r5ssid",
	},
	{
		//"v5ssid", //voice ssid is not applied in GAPD-7100
		"data5ssid",
		"m5ssid",
		"r5ssid",
		"r25ssid",
		"r35ssid",
		"r45ssid",
		"r55ssid",
	}
};

int get_sta_dev_mon(FILE *fp, int numif, int numbss)
{
	int i, j, k;
	char mon_rslt[128] = {0, };
	int ret = 0;

	char dotted_mac[20] = {0, };
	int assoc_time;
	struct tm *tt;

	int if_idx;

	if (!fp)
		return -1;

	memset(info, 0, sizeof(wl_client_info_t) * 128);

	// make STAs per bss statistics
	for (i = 0; i < numif; i++) {
		for (j = 0; j < numbss; j++) {

			fprintf(fp, "&%s_dev_mon=", ssid_name[i][j]);

			//idx 1 : 2.4GHz
			//idx 0 : 5GHz
			if_idx = i ^ 1;
			ret = get_wl_client_info(if_idx, j - 1);
			if (ret > 0) {
				for (k = 0; k < ret; k++) {
					//sta num??
					memset(mon_rslt, 0, 128);

					//macAddr
					snprintf(dotted_mac, sizeof(dotted_mac), "%s", info[k].macAddr);
					conv_mac_format(dotted_mac);

					//assocStartTime
					if (info[k].assocTime > 1464739200UL)	// if time is after "2016/06/01 00:00:00"
						assoc_time = info[k].assocTime;
					else
						assoc_time = 0;

					tt = localtime((time_t *)&assoc_time);

					fprintf(fp, "%s,%d,%04d%02d%02d%02d%02d%02d,%lu,%lu",
					        info[k].macAddr,
					        info[k].rssi,
					        tt->tm_year + 1900,
					        tt->tm_mon + 1,
					        tt->tm_mday,
					        tt->tm_hour,
					        tt->tm_min,
					        tt->tm_sec,
					        info[k].tx_bytes,
					        info[k].rx_bytes);

					if ((ret > 1) && (k - 1 < ret))
						fprintf(fp, "|");

				}
			} else
				continue;
		}
	}

	return 1;
}

char *get_wl_client_info_qms(char *val, int bufsz, int idx, int subidx)
{
	int ret = 0;
	int i = 0;
	int len = 0;
	int tt = 0;
	struct tm *p_tm_t;
	int auth;
	char auth_type;

	char buf[128] = {0, };

	if (!val)
		return NULL;

	ret = get_wl_client_info(idx, subidx);

	for (i = 0; i < ret; i++) {
		//reporting
		//mac, ip, rssi, assoc time, auth_type

		//1. mac
		//0000.0000.0000
		get_assocDevice_mac(buf, sizeof(buf), i);
		conv_mac_format(buf);
		len += snprintf(val + len, bufsz - len, "%s,", buf);

		//2. ip
		get_assocDevice_ip(buf, sizeof(buf), i);
		len += snprintf(val + len, bufsz - len, "%s,", buf);

		//3. rssi
		len += snprintf(val + len, bufsz - len, "%d,", get_assocDevice_rssi(i));

		//4. assoc time
		tt = get_assocDevice_assocTime(i);
		p_tm_t = localtime((time_t *)&tt);

		len += snprintf(val + len, bufsz - len, "%04d%02d%02d%02d%02d%02d",
		                p_tm_t->tm_year + 1900, p_tm_t->tm_mon + 1,
		                p_tm_t->tm_mday, p_tm_t->tm_hour,
		                p_tm_t->tm_min, p_tm_t->tm_sec);

		//5. auth_type
		//1:none, 2:MAC, 3:MD5, 4:MAC+MD5, 5:EAP, 6:WEB, 7:WEB+MAC
		auth = get_assocDevice_auth_info(i);
		//len += snprintf(val + len, bufsz - len, "%d", auth);

		if (subidx == -1) { //Not member
			//Do nothing.
			//Do not need addtional information anymore.
		} else {
			if (auth == 1)  {
				len += snprintf(val + len, bufsz - len, ",%d,%d",
				                get_ssid_encryption(idx, subidx), auth - 1);
			} else {
				if (auth == 5)
					auth = 2;

				auth_type = get_assocDevice_auth_type(i);

				if (auth_type == 'M')
					len += snprintf(val + len, bufsz - len, ",%d", 1);
				else if (auth_type == 'E')
					len += snprintf(val + len, bufsz - len, ",%d", auth - 1);
				else if (auth_type == 'W')
					len += snprintf(val + len, bufsz - len, "%s", ",4");
			}
		}

		if (i < ret - 1)
			len += snprintf(val + len, bufsz - len, "%s", "|");
	}

	val[len] = '\0';

	return val;
}

void get_assocDevice_mac(char *buf, int size, int idx)
{
	strncpy(buf, info[idx].macAddr, size);
}

void get_assocDevice_ip(char *buf, int size, int idx)
{
	strncpy(buf, info[idx].ipAddr, size);
}

int get_assocDevice_rssi(int idx)
{
	return info[idx].rssi;
}

int get_assocDevice_auth_info(int idx)
{
	return (info[idx].auth_info);
}

unsigned int get_assocDevice_assocTime(int idx)
{
	return info[idx].assocTime;
}

char get_assocDevice_auth_type(int idx)
{
	return info[idx].auth_type;
}

unsigned int err_sav[MAXIDX][MAXSUBIDX];


//Maybe This function is called in IPDM.
//GAPD7100 doesn't use this function.
void get_save_err_cnt()
{
	int i, k;
	FILE *fp = NULL;

	memset(err_sav, 0, sizeof(err_sav));
	fp = fopen(IPDM_WL_ERR_SAV_FILE, "r");
	if (!fp)
		return;
	for (i = 0; i < MAXIDX; i++) {
		for (k = 0; k < MAXSUBIDX;) {
			if (fscanf(fp, "%u ", &err_sav[i][k]) == 0)
				break;
		}
	}

	fclose(fp);
}

unsigned int get_wl_err_cnt(int idx, int subidx)
{
	unsigned int res;
	char prefix[32] = {0, };

	get_wlan_ifname_from_idx(prefix, sizeof(prefix), idx, subidx);

	res = get_traffic(prefix, 11);
	res += get_traffic(prefix, 3);

	return res;
}

#if 0
static void save_wl_err_cnt(void)
{
	FILE *fp = NULL;
	int i, j;

	fp = fopen(IPDM_WL_ERR_SAV_FILE, "w");
	if (fp) {
		for (i = 0; i < MAXIDX; i++) {
			for (j = 0; j < MAXSUBIDX; j++)
				fprintf(fp, "%u ", err_sav[i][j]);
			fprintf(fp, "\n");
		}
		fclose(fp);
	}
}
#endif

int set_wl_err_ini(int val, int idx, int subidx)
{
	char prefix[32] = {0, };

	if (val != 1)
		return 0;

	if ((idx < 0 || idx >= MAXIDX) || (subidx < 0 || subidx > MAXSUBIDX))
		return 0;

	get_wlan_ifname_from_idx(prefix, sizeof(prefix), idx, subidx);

	err_sav[idx][subidx] = get_traffic(prefix, 3);
	err_sav[idx][subidx] += get_traffic(prefix, 11);

	//save_wl_err_cnt();

	return 0;
}

unsigned long long get_dev_traffic_64(int pn, int isTx)
{
	uint64 byte = 0;

	if (pn >= LAN_PORT1 && pn <= WAN_PORT) {	//WAN + LAN
		if (IS_BRIDGE_MODE && pn == WAN_PORT)
			return 0;
		else {
			get_port_traffic(pn, &byte, isTx);
			return byte;
		}
	} else if (pn >= 10) {	//WLAN
		//in GAPD7000 source code
		//10 ~ 19(0) : 2.4GHz
		//20 ~ 29(1) : 5GHz
		int idx = (pn / 10) - 1;
		int subidx = (pn % 10) - 2;
		unsigned int loop_cnt = 0;

		//idx -> revert value;
		//0 : 5GHz
		//1 : 2.4GHz
		idx = idx ^ 1;

		byte = get_wl_traffic(idx, subidx, isTx);
		loop_cnt = get_ssid_loop_cnt(idx, subidx, isTx);
		byte += (loop_cnt * ((uint64)0xffffffff + 1));
		return byte;
	}

	return 0;
}

unsigned int get_dev_traffic(int pn, int isTx)
{
	return (unsigned int)(get_dev_traffic_64(pn, isTx) & 0xffffffff);
}

unsigned int get_wl_traffic(int idx, int subidx, int isTx)
{
	int ret;
	char tmp[16] = {0, };
	char str[32] = {0, };
	char *arg[2];
	char buf[128] = {0, };
	FILE *fp = NULL;

	get_wlan_ifname_from_idx(tmp, sizeof(tmp), idx, subidx);

	snprintf(str, sizeof(str), "/proc/%s/stats", tmp);
	fp = fopen(str, "r");
	if (fp == NULL)
		return 0;

	memset(tmp, 0, sizeof(tmp));
	memset(str, 0, sizeof(str));

	if (isTx)
		snprintf(tmp, sizeof(tmp), "%s", "tx");
	else
		snprintf(tmp, sizeof(tmp), "%s", "rx");
	snprintf(str, sizeof(str), "%s_only_data_bytes", tmp);

	while (fgets(buf, sizeof(buf), fp) != NULL) {

		if (strstr(buf, str)) {
			ret = ystrargs(buf, arg, 2, ":", 0);

			if (ret != 2) {
				fclose(fp);

				return 0;
			}
			fclose(fp);

			return strtoul(arg[1], NULL, 10);
		}
	}
	fclose(fp);

	return 0;
}

int get_ssid_hidden(int idx, int subidx)
{
	char key[32] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_HIDDEN_SSID", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_HIDDEN_SSID", idx, subidx);

	if (nvram_match_r(key, "1"))
		return 1;
	else
		return 0;
}

int set_ssid_hidden(int val, int idx, int subidx)
{
	char key[32] = {0, };

	if (val != 0 && val != 1)
		return 0;

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_HIDDEN_SSID", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_HIDDEN_SSID", idx, subidx);

	nvram_set(key, val ? "1" : "0");

	return 1;
}

int get_ssid_inner_con(int idx, int subidx)
{
#if 0
	char key[32] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "wl%d_ap_isolate", idx);
	else
		snprintf(key, sizeof(key), "wl%d.%d_ap_isolate", idx, subidx);

	if (nvram_match_r(key, "1"))
		return 0;
	return 1;
#endif
	return 0;
}

int set_ssid_inner_con(int var, int idx, int subidx)
{
#if 0
	char key[32] = {0, };

	if (var != 0 && var != 1)
		return 0;

	if (subidx == -1)
		snprintf(key, sizeof(key), "wl%d_ap_isolate", idx);
	else
		snprintf(key, sizeof(key), "wl%d.%d_ap_isolate", idx, subidx);

	if (var == 1)
		nvram_set(key, "0");
	else
		nvram_set(key, "1");

	return 1;
#endif
	return 0;
}

int get_ssid_web_access(int idx, int subidx)
{
#if 0
	char key[32] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "wl%d_web_access", idx);
	else
		snprintf(key, sizeof(key), "wl%d.%d_web_access", idx, subidx);

	if (nvram_match_r(key, "1"))
		return 1;

	return 0;
#endif
	return 0;
}

int set_ssid_web_access(int var, int idx, int subidx)
{
#if 0
	char key[32] = {0, };
	char val[4] = {0, };

	if (var != 0 && var != 1)
		return 0;

	snprintf(val, sizeof(val), "%d", var);
	if (subidx == -1)
		snprintf(key, sizeof(key), "wl%d_web_access", idx);
	else
		snprintf(key, sizeof(key), "wl%d.%d_web_access", idx, subidx);

	if (!nv_strcmp(val, "1"))
		nvram_set(key, "1");
	else
		nvram_set(key, "0");

	return 1;
#endif
	return 0;
}

int get_vlan_id(int idx, int subidx)
{
#if 0
	char key[32] = {0, }, tmp[8] = {0, };
	int res;

	if (subidx == -1)
		snprintf(key, sizeof(key), "wl%d_vlan_id", idx);
	else
		snprintf(key, sizeof(key), "wl%d.%d_vlan_id", idx, subidx);

	res = atoi(nvram_safe_get_r(key, tmp, sizeof(tmp)));
	return res;
#endif
	return 0;
}

int set_vlan_id(int res, int idx, int subidx)
{
#if 0
	char key[32] = {0, }, val[8] = {0, };

	if (res < 0 || res >= 4096)
		return 0;

	if (subidx == -1)
		snprintf(key, sizeof(key), "wl%d_vlan_id", idx);
	else
		snprintf(key, sizeof(key), "wl%d.%d_vlan_id", idx, subidx);

	snprintf(val, sizeof(val), "%d", res);
	nvram_set(key, val);

	return 1;
#endif
	return 0;
}

int get_ssid_lgauth(int idx, int subidx)
{
	char param[32] = {0, };
	char val[8] = {0, };

	if (subidx == -1)
		snprintf(param, sizeof(param), "x_WLAN%d_LGAUTH", idx);
	else
		snprintf(param, sizeof(param), "x_WLAN%d_VAP%d_LGAUTH", idx, subidx);

	return (atoi(nvram_safe_get_r(param, val, sizeof(val))) + 1);
}

int set_ssid_lgauth(int res, int idx, int subidx)
{
	char filename[64] = {0, };

	memset(filename, 0, sizeof(filename));

	if (subidx == -1)
		snprintf(filename, sizeof(filename), "/tmp/cwmp/.wlan%d_1x_auth", idx);
	else
		snprintf(filename, sizeof(filename), "/tmp/cwmp/.wlan%d_vap%d_1x_auth", idx, subidx);

	unlink(filename);
	yecho(filename, "%d", res);

	return 1;
}

int get_ssid_encryption(int idx, int subidx)
{
	int res = 0, encrypt, val, wepkeyidx, cipher;
	char prefix[12] = {0, };
	char param[32] = {0, };
	char tmp[8] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "WLAN%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "WLAN%d_VAP%d", idx, subidx);

	snprintf(param, sizeof(param), "%s_ENCRYPT", prefix);

	encrypt = atoi(nvram_get_r_def(param, tmp, sizeof(tmp), "0"));

	if (encrypt == 1) { // WEP
		snprintf(param, sizeof(param), "%s_x_LGAUTH", prefix);
		val = atoi(nvram_get_r_def(param, tmp, sizeof(tmp), "0"));
		if (val == 4) { // Dynamic WEP
			res = 14;
		} else {
			snprintf(param, sizeof(param), "%s_WEP_DEFAULT_KEY", prefix);
			wepkeyidx = atoi(nvram_get_r_def(param, tmp, sizeof(tmp), "0"));

			snprintf(param, sizeof(param), "%s_WEP", prefix);
			val = atoi(nvram_get_r_def(param, tmp, sizeof(tmp), "1"));
			if (val == 1) // WEP-64
				res = 2 + wepkeyidx;
			else // WEP-128
				res = 6 + wepkeyidx;
		}
	} else if (encrypt == 2) { // WPA
		snprintf(param, sizeof(param), "%s_WPA_CIPHER_SUITE", prefix);
		cipher = atoi(nvram_get_r_def(param, tmp, sizeof(tmp), "1"));

		snprintf(param, sizeof(param), "%s_WPA_AUTH", prefix);
		val = atoi(nvram_get_r_def(param, tmp, sizeof(tmp), "1"));
		if (cipher == 1) { // TKIP
			if (val == 1) // RADIUS
				res = 15;
			else // PSK
				res = 10;
		} else { // AES
			if (val == 1)
				res = 16;
			else // PSK
				res = 11;
		}
	} else if (encrypt == 4) { // WPA2
		snprintf(param, sizeof(param), "%s_WPA2_CIPHER_SUITE", prefix);
		cipher = atoi(nvram_get_r_def(param, tmp, sizeof(tmp), "1"));

		snprintf(param, sizeof(param), "%s_WPA_AUTH", prefix);
		val = atoi(nvram_get_r_def(param, tmp, sizeof(tmp), "1"));
		if (cipher == 1) { // TKIP
			if (val == 1) // RADIUS
				res = 17;
			else // Personal
				res = 12;
		} else { // AES
			if (val == 1) // RADIUS
				res = 18;
			else // Personal
				res = 13;
		}
	} else { // OPEN
		res = 1;
	}

	return res;
}

int set_ssid_encryption(int res, int idx, int subidx)
{
	char filename[64] = {0, };

	memset(filename, 0, sizeof(filename));

	if (subidx == -1)
		snprintf(filename, sizeof(filename), "/tmp/cwmp/.wlan%d_encryption", idx);
	else
		snprintf(filename, sizeof(filename), "/tmp/cwmp/.wlan%d_vap%d_encryption", idx, subidx);

	unlink(filename);
	yecho(filename, "%d", res);

	return 1;
}

static int toHex(unsigned char c)
{
	c = toupper(c);
	if ((c >= 'A') && (c <= 'F'))
		return c - 'A' + 10;
	if ((c >= '0') && (c <= '9'))
		return c - '0';
	return 0;
}

static int hex_to_ascii(unsigned char c, unsigned char d)
{
	return (toHex(c) << 4) + toHex(d);
}

char *get_ssid_encryptionkey(char *val, int bufsz, int idx, int subidx)
{
	int i;
	char prefix[12] = {0, };
	char param[32] = {0, };
	char tmp[80] = {0, }, tmp1[8] = {0, };
	int value, wepkeyidx, ishex, weplen;
	char buf = 0;
	char key[256] = {0, };
	char enc_msg[1024] = {0, };
	int enc_len = 0;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "WLAN%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "WLAN%d_VAP%d", idx, subidx);

	snprintf(param, sizeof(param), "%s_ENABLE_1X", prefix);
	value = atoi(nvram_get_r_def(param, tmp, sizeof(tmp), "0"));

	if (value == 0) {
		snprintf(param, sizeof(param), "%s_ENCRYPT", prefix);
		value = atoi(nvram_get_r_def(param, tmp, sizeof(tmp), "0"));
		if (value == 1) { // WEP
			snprintf(param, sizeof(param), "%s_WEP_DEFAULT_KEY", prefix);
			wepkeyidx = atoi(nvram_safe_get_r(param, tmp, sizeof(tmp)));

			snprintf(param, sizeof(param), "%s_WEP", prefix);
			value = atoi(nvram_safe_get_r(param, tmp, sizeof(tmp)));
			if (value == 1) // 64bit
				snprintf(param, sizeof(param), "%s_WEP64_KEY%d", prefix, wepkeyidx + 1);
			else // 128bit
				snprintf(param, sizeof(param), "%s_WEP128_KEY%d", prefix, wepkeyidx + 1);

			nvram_safe_get_r(param, tmp, sizeof(tmp));

			snprintf(param, sizeof(param), "%s_WEP_KEY_TYPE", prefix);
			ishex = atoi(nvram_get_r_def(param, tmp1, sizeof(tmp1), "0"));

			if (ishex != 1) { // ascii
				char out[16] = {0, };
				int outlen = 0;

				weplen = STRLEN(tmp);
				for (i = 0; i < weplen; i++) {
					if (i % 2 != 0)
						outlen += snprintf(&out[outlen], sizeof(out) - outlen, "%c", hex_to_ascii(buf, tmp[i]));
					else
						buf = tmp[i];
				}
				snprintf(key, sizeof(key), "%s", out);
			} else
				snprintf(key, sizeof(key), "%s", tmp);
		} else if (value == 2 || value == 4) { // WPA or WPA2
			snprintf(param, sizeof(param), "%s_WPA_PSK", prefix);
			nvram_safe_get_r(param, key, sizeof(key));
		}
	}

	enc_len = percent_encode(key, enc_msg, sizeof(enc_msg));
	enc_msg[enc_len] = 0;

	snprintf(val, bufsz, "%s", enc_msg);

	return val;
}

//APACRTL-452
char *get_ssid_encryptionkey_wep(char *val, int bufsz, int idx, int subidx, int mode, int keyidx)
{
	int i;
	char prefix[12] = {0, };
	char midfix[16] = {0, };
	char param[32] = {0, };
	char tmp[80] = {0, }, tmp1[8] = {0, }, tmp2[8] = {0, };
	int ishex, weplen;
	char buf = 0;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "WLAN%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "WLAN%d_VAP%d", idx, subidx);

	if (mode >= 2 && mode <= 5) { // 64bit
		snprintf(param, sizeof(param), "%s_WEP64_KEY%d", prefix, keyidx);
		snprintf(midfix, sizeof(midfix), "%s", "WEP64");
	} else {	// 128bit
		snprintf(param, sizeof(param), "%s_WEP128_KEY%d", prefix, keyidx);
		snprintf(midfix, sizeof(midfix), "%s", "WEP128");
	}

	nvram_safe_get_r(param, tmp, sizeof(tmp));

	snprintf(param, sizeof(param), "%s_%s_KEY_TYPE%d", prefix, midfix, keyidx);
	if (nvram_get_r(param, tmp1, sizeof(tmp1)) == NULL)
		snprintf(param, sizeof(param), "%s_WEP_KEY_TYPE", prefix);

	ishex = atoi(nvram_get_r_def(param, tmp2, sizeof(tmp2), "0"));

	if (ishex != 1) { // ascii
		char out[16] = {0, };
		int outlen = 0;

		weplen = STRLEN(tmp);
		for (i = 0; i < weplen; i++) {
			if (i % 2 != 0)
				outlen += snprintf(&out[outlen], sizeof(out) - outlen, "%c", hex_to_ascii(buf, tmp[i]));
			else
				buf = tmp[i];
		}
		snprintf(val, bufsz, "%s", out);
	} else
		snprintf(val, bufsz, "%s", tmp);

	return val;
}

int set_ssid_encryptionkey(char *val, int idx, int subidx)
{
	char filename[128] = {0, };

	memset(filename, 0, sizeof(filename));

	if (subidx == -1)
		snprintf(filename, sizeof(filename), "/tmp/cwmp/.wlan%d_encryption_key", idx);
	else
		snprintf(filename, sizeof(filename), "/tmp/cwmp/.wlan%d_vap%d_encryption_key", idx, subidx);

	unlink(filename);
	yecho(filename, "%s", val);

	return 1;
}

#ifdef __SERVICE_LGU_ENT__
void get_customer_web(char *val, int bufsz, int idx, int subidx)
{
#if 0
	char key[32] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "wl%d_customer_web", idx);
	else
		snprintf(key, sizeof(key), "wl%d.%d_customer_web", idx, subidx);

	if (nvram_match_r(key, "1"))
		snprintf(val, bufsz, "%s", "1");
	else
		snprintf(val, bufsz, "%s", "0");
#endif
}

int set_customer_web(char *val, int idx, int subidx)
{
#if 0
	char key[32] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "wl%d_customer_web", idx);
	else
		snprintf(key, sizeof(key), "wl%d.%d_customer_web", idx, subidx);

	if (nv_strcmp(val, "0") && nv_strcmp(val, "1"))
		return 0;

	nvram_set(key, val);
	return 1;
#endif
	return 0;
}

void get_customer_web_url(char *val, int bufsz, int idx, int subidx)
{
#if 0
	char key[32] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "wl%d_customer_web_url", idx);
	else
		snprintf(key, sizeof(key), "wl%d.%d_customer_web_url", idx, subidx);

	nvram_safe_get_r(key, val, bufsz);
#endif
}

int set_customer_web_url(char *val, int idx, int subidx)
{
#if 0
	char key[32] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "wl%d_customer_web_url", idx);
	else
		snprintf(key, sizeof(key), "wl%d.%d_customer_web_url", idx, subidx);

	if (STRLEN(val) == 0)
		return 0;

	nvram_set(key, val);
	return 1;
#endif
	return 0;
}
#endif //__SERVICE_LGU_ENT__

#define MAX_MA_RESTRICT_ENTRY		20
int get_mac_auth_restrict_list(const char *prefix, char *val, int sz)
{
	int len = 0;
	char str[32] = {0, };
	char buf[32] = {0, };
	int i;

	// add entries from nvram
	for (i = 0; i < MAX_MA_RESTRICT_ENTRY; i++) {
		snprintf(str, sizeof(str), "%s_mac_deny%d", prefix, i);
		nvram_safe_get_r(str, buf, sizeof(buf));
		if (buf[0]) {
			if (len + STRLEN(buf) >= sz)
				break;
			if (len == 0)
				len = snprintf(val, sz, "%s", conv_mac_format(buf));
			else
				len += snprintf(val + len, sz - len, "|%s", conv_mac_format(buf));
		} else {
			break;
		}
	}
	return len;
}

int add_mac_auth_restrict_list(const char *prefix, char *val)
{
#if 0
	int find = -1;
	char str[32] = {0, };
	char buf[32] = {0, };
	char convMac[32] = {0, };
	int i;

	if (STRLEN(val) > 0) {
		unsigned int x, y, z;
		if (sscanf(val, "%x.%x.%x", &x, &y, &z) == 3) {
			snprintf(convMac, sizeof(convMac), "%02x:%02x:%02x:%02x:%02x:%02x",
			         (x & 0xff00) >> 8, (x & 0xff), (y & 0xff00) >> 8, (y & 0xff), (z & 0xff00) >> 8, (z & 0xff));
		} else {
			return 0;
		}
	} else
		return 0;

	// add entries from nvram
	for (i = 0; i < MAX_MA_RESTRICT_ENTRY; i++) {
		snprintf(str, sizeof(str), "%s_mac_deny%d", prefix, i);
		nvram_safe_get_r(str, buf, sizeof(buf));
		if (buf[0]) {
			if (STRNCASECMP(convMac, buf) == 0) {
				find = i;
				break;
			}
		} else {
			break;
		}
	}

	if (find >= 0 || i == MAX_MA_RESTRICT_ENTRY)
		return 0;
	else
		nvram_set(str, convMac);
	return 1;
#endif
	return 0;
}

int del_mac_auth_restrict_list(const char *prefix, char *val)
{
#if 0
	int find = -1;
	char str[32] = {0, };
	char buf[32] = {0, };
	char convMac[32] = {0, };
	int i;

	if (STRLEN(val) > 0) {
		unsigned int x, y, z;
		if (sscanf(val, "%x.%x.%x", &x, &y, &z) == 3) {
			snprintf(convMac, sizeof(convMac), "%02x:%02x:%02x:%02x:%02x:%02x",
			         (x & 0xff00) >> 8, (x & 0xff), (y & 0xff00) >> 8, (y & 0xff), (z & 0xff00) >> 8, (z & 0xff));
		} else {
			return 0;
		}
	} else
		return 0;
	// add entries from nvram
	for (i = 0; i < MAX_MA_RESTRICT_ENTRY; i++) {
		snprintf(str, sizeof(str), "%s_mac_deny%d", prefix, i);
		nvram_safe_get_r(str, buf, sizeof(buf));
		if (buf[0]) {
			if (STRNCASECMP(convMac, buf) == 0) {
				find = i;
				break;
			}
		} else {
			break;
		}
	}
	if (find < 0 || i == MAX_MA_RESTRICT_ENTRY)
		return 0;
	for (i = find; i < (MAX_MA_RESTRICT_ENTRY - 1); i++) {
		snprintf(str, sizeof(str), "%s_mac_deny%d", prefix, i + 1);
		nvram_safe_get_r(str, buf, sizeof(buf));
		nvram_unset(str);
		snprintf(str, sizeof(str), "%s_mac_deny%d", prefix, i);
		if (buf[0])
			nvram_set(str, buf);
		else
			nvram_unset(str);

	}
	return 1;
#endif
	return 0;
}

char *get_auth_limit_list(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, };

	if (!val)
		return val;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "WLAN%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "WLAN%d_VAP%d", idx, subidx);

	get_mac_auth_restrict_list(prefix, val, bufsz);

	return val;
}

int add_1x_auth_list(char *val, int idx, int subidx)
{
#if 0
	char prefix[16] = {0, };
	int ret;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	ret = add_mac_auth_restrict_list(prefix, val);

	return ret;
#endif
	return 0;
}

int del_1x_auth_list(char *val, int idx, int subidx)
{
#if 0
	char prefix[16] = {0, };
	int ret;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	ret = del_mac_auth_restrict_list(prefix, val);

	return ret;
#endif
	return 0;
}

int get_lgauth_info_flag(int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	char buf[8] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	return (atoi(nvram_safe_get_r(strncat_r(prefix, "_lgauth_info_flag", tmp, sizeof(tmp)), buf, sizeof(buf))) + 1);
}

int set_lgauth_info_flag(int var, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	char val[4] = {0, };

	if (var < 0 || var > 2)
		return 0;

	snprintf(val, sizeof(val), "%d", var);
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_lgauth_info_flag", tmp, sizeof(tmp)), val);

	return 1;
}

void get_radius_domain(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_domain", tmp, sizeof(tmp)), val, bufsz);
}

int set_radius_domain(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_domain", tmp, sizeof(tmp)), val);

	return 1;
}

void get_radius_ip(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_ipaddr", tmp, sizeof(tmp)), val, bufsz);
}

int set_radius_ip(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	struct in_addr ip;

	if (STRLEN(val) == 0 || inet_aton(val, &ip) == 0)
		return 0;
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_ipaddr", tmp, sizeof(tmp)), val);

	return 1;
}

void get_radius_port(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_port", tmp, sizeof(tmp)), val, bufsz);
}

int set_radius_port(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	char *end;
	int res;

	res = strtol(val, &end, 10);
	if (STRLEN(val) == 0 || STRLEN(end) > 0 || res < 0 || res > 65535)
		return 0;
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_port", tmp, sizeof(tmp)), val);

	return 1;
}

void get_radius_shared_secret(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_key", tmp, sizeof(tmp)), val, bufsz);
}

int set_radius_shared_secret(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (STRLEN(val) == 0)
		return 0;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_key", tmp, sizeof(tmp)), val);

	return 1;
}

void get_radius_domain2(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_domain2", tmp, sizeof(tmp)), val, bufsz);
}

int set_radius_domain2(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (STRLEN(val) == 0)
		return 0;
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_domain2", tmp, sizeof(tmp)), val);
	return 1;
}

void get_radius_ip2(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_ip2", tmp, sizeof(tmp)), val, bufsz);
}

int set_radius_ip2(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	struct in_addr ip;

	if (STRLEN(val) == 0 || inet_aton(val, &ip) == 0)
		return 0;
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_ip2", tmp, sizeof(tmp)), val);

	return 1;
}

void get_radius_port2(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_port2", tmp, sizeof(tmp)), val, bufsz);
}

int set_radius_port2(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	char *end;
	int res;

	res = strtol(val, &end, 10);
	if (STRLEN(val) == 0 || STRLEN(end) > 0 || res < 0 || res > 65535)
		return 0;
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_port2", tmp, sizeof(tmp)), val);

	return 1;
}

void get_radius_shared_secret2(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_key2", tmp, sizeof(tmp)), val, bufsz);
}

int set_radius_shared_secret2(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (STRLEN(val) == 0)
		return 0;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_key2", tmp, sizeof(tmp)), val);

	return 1;
}

void get_acct_domain(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_acct_domain", tmp, sizeof(tmp)), val, bufsz);
}

int set_acct_domain(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_acct_domain", tmp, sizeof(tmp)), val);

	return 1;
}

void get_acct_ip(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_acct_ip", tmp, sizeof(tmp)), val, bufsz);
}

int set_acct_ip(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	struct in_addr ip;

	if (STRLEN(val) == 0 || inet_aton(val, &ip) == 0)
		return 0;
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_acct_ip", tmp, sizeof(tmp)), val);

	return 1;
}

void get_acct_port(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_acct_port", tmp, sizeof(tmp)), val, bufsz);
}

int set_acct_port(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	char *end;
	int res;

	res = strtol(val, &end, 10);
	if (STRLEN(val) == 0 || STRLEN(end) > 0 || res < 0 || res > 65535)
		return 0;
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_acct_port", tmp, sizeof(tmp)), val);

	return 1;
}

void get_acct_shared_secret(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_acct_key", tmp, sizeof(tmp)), val, bufsz);
}

int set_acct_shared_secret(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (STRLEN(val) == 0)
		return 0;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_acct_key", tmp, sizeof(tmp)), val);

	return 1;
}

void get_acct_domain2(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_acct_domain2", tmp, sizeof(tmp)), val, bufsz);
}

int set_acct_domain2(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (STRLEN(val) == 0)
		return 0;
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_acct_domain2", tmp, sizeof(tmp)), val);

	return 1;
}

void get_acct_ip2(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_acct_ip2", tmp, sizeof(tmp)), val, bufsz);
}

int set_acct_ip2(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	struct in_addr ip;

	if (STRLEN(val) == 0 || inet_aton(val, &ip) == 0)
		return 0;
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_acct_ip2", tmp, sizeof(tmp)), val);

	return 1;
}

void get_acct_port2(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_acct_port2", tmp, sizeof(tmp)), val, bufsz);
}

int set_acct_port2(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	char *end;
	int res;

	res = strtol(val, &end, 10);
	if (STRLEN(val) == 0 || STRLEN(end) > 0 || res < 0 || res > 65535)
		return 0;
	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_acct_port2", tmp, sizeof(tmp)), val);

	return 1;
}

void get_acct_shared_secret2(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_radius_acct_key2", tmp, sizeof(tmp)), val, bufsz);
}

int set_acct_shared_secret2(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (STRLEN(val) == 0)
		return 0;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_radius_acct_key2", tmp, sizeof(tmp)), val);

	return 1;
}

void get_lgauth_web(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	char buf[4];

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	snprintf(val, bufsz, "%d", atoi(nvram_safe_get_r(strncat_r(prefix, "_lgauth_web", tmp, sizeof(tmp)), buf, sizeof(buf))));
}

int set_lgauth_web(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (nv_strcmp(val, "0") && nv_strcmp(val, "1") && nv_strcmp(val, "2"))
		return 0;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_lgauth_web", tmp, sizeof(tmp)), val);
	return 1;
}

void get_lgauth_web_redir_url(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_safe_get_r(strncat_r(prefix, "_lgauth_web_redirect_url", tmp, sizeof(tmp)), val, bufsz);
}

int set_lgauth_web_redir_url(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	char buf[256] = {0, }, *p;

	if (STRLEN(val) == 0)
		return 0;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	p = strstr(val, "http://");
	if (p != NULL)
		snprintf(buf, sizeof(buf), "%s", val);
	else
		snprintf(buf, sizeof(buf), "http://%s", val);
	nvram_set(strncat_r(prefix, "_lgauth_web_redirect_url", tmp, sizeof(tmp)), buf);
	return 1;
}

void get_web_auth_info_flag(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	if (nvram_match_r(strncat_r(prefix, "_web_auth_info_flag", tmp, sizeof(tmp)), "1"))
		snprintf(val, bufsz, "%s", "1");
	else
		snprintf(val, bufsz, "%s", "0");
}

int set_web_auth_info_flag(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };

	if (nv_strcmp(val, "0") && nv_strcmp(val, "1"))
		return 0;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_web_auth_info_flag", tmp, sizeof(tmp)), val);
	return 1;
}

void get_web_auth_port(char *val, int bufsz, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	char buf[64] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	snprintf(val, bufsz, "%d", atoi(nvram_safe_get_r(strncat_r(prefix, "_web_auth_port", tmp, sizeof(tmp)), buf, sizeof(buf))));
}

int set_web_auth_port(char *val, int idx, int subidx)
{
	char prefix[16] = {0, }, tmp[64] = {0, };
	char *end;
	int res;

	res = strtol(val, &end, 10);
	if (STRLEN(val) == 0 || STRLEN(end) > 0 || res < 0 || res > 65535)
		return 0;

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "wl%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "wl%d.%d", idx, subidx);

	nvram_set(strncat_r(prefix, "_web_auth_port", tmp, sizeof(tmp)), val);

	return 1;
}

int get_bonding_master_ch_idx(int idx)
{
	int ch = 0;
	int bond_type = 0;
	int master_ch_idx = 0;
	int ref_ch = 0;

	char wl_ifname[16] = {0, };
	bss_info bss;

	snprintf(wl_ifname, sizeof(wl_ifname), "wlan%d", idx);

	if (getWlBssInfo(wl_ifname, &bss, NULL, NULL) < 0) {
		fprintf(stderr, "%s getWlBssInfo error.\n", __FUNCTION__);
		return -1;
	}

	ch = get_current_channel(idx);

	// TODO : 자동 채널일때도 괜찮나?
	if (idx == 0) { //5GHz
		bond_type = nvram_atoi("WLAN0_CHANNEL_BONDING", 0);

		switch (bond_type) {
		case BAND_20MHZ:
			master_ch_idx = 0;
			break;

		case BAND_40MHZ:
			if (nvram_atoi("WLAN0_CONTROL_SIDEBAND", 0) == 0) //Upper
				master_ch_idx = 0;
			else //Lower
				master_ch_idx = 1;
			break;

		case BAND_80MHZ:
			if (ch <= 48)
				ref_ch = 48;
			else if (ch <= 64)
				ref_ch = 64;
			else if (ch <= 112)
				ref_ch = 112;
			else if (ch <= 161)
				ref_ch = 161;

			master_ch_idx = 3 - ((ref_ch - ch) / 4);

			break;

		default:
			fprintf(stderr, "%s Check channel bonding type.\n", __FUNCTION__);
			break;
		}				/* -----  end switch  ----- */

	} else { //2.4GHz
		bond_type = nvram_atoi("WLAN1_CHANNEL_BONDING", 0);

		switch (bond_type) {
		case BAND_20MHZ:
			master_ch_idx = 0;
			break;

		case BAND_40MHZ:
			if (nvram_atoi("WLAN1_CONTROL_SIDEBAND", 0) == 0) //Upper
				master_ch_idx = 0;
			else //Lower
				master_ch_idx = 1;
			break;

		default:
			fprintf(stderr, "%s Check channel bonding type.\n", __FUNCTION__);
			break;
		}
	}

	return master_ch_idx;
}

int set_bonding_master_ch_idx(int val, int idx)
{
	return 0;
}

//APACRTL-402
int get_ch_bonding_use(int idx)
{
	char wl_ifname[16] = {0, };
	bss_info bss;
	int bw, sb;

	snprintf(wl_ifname, sizeof(wl_ifname), "wlan%d", idx);

	if (getWlBssInfo(wl_ifname, &bss, &bw, &sb) < 0) {
		fprintf(stderr, "Get bssinfo failed!\n");
		return -1;
	}

	if (bw == 80) {
		return 2;
	} else if (bw == 40) {
		if (idx == 0) {
			return 1;
		} else {
			if (sb == 'A')
				return 1;	//Lower
			else
				return 2;	//Upper
		}
	} else
		return 0;
}

//APACRTL-404
int set_ch_bonding_use(int res, int idx)
{
	char filename[64] = {0, };

	if (res < BAND_20MHZ || res > BAND_80MHZ)
		return -9007;

	snprintf(filename, sizeof(filename), "/tmp/cwmp/.wlan%d_width", idx);
	unlink(filename);

	yecho(filename, "%d", res);

	return 1;
}

int get_auto_chan_use(int idx)
{
	char key[32] = {0, };

	snprintf(key, sizeof(key), "WLAN%d_CHANNEL", idx);

	if (nvram_match_r(key, "0"))
		return 1;

	return 0;
}

//APACRTL-404
int set_auto_chan_use(int res, int idx)
{
	char filename[64] = {0, };

	snprintf(filename, sizeof(filename), "/tmp/cwmp/.wlan%d_auto", idx);
	unlink(filename);

	if (res == 1)
		yecho(filename, "%d", 0);
	else
		yecho(filename, "%d", get_current_channel(idx));

	return 1;
}

int get_current_channel(int idx)
{
	char wl_ifname[16] = {0, };
	int res = 0;
	bss_info bss;

	snprintf(wl_ifname, 15, "wlan%d", idx);

	if (getWlBssInfo(wl_ifname, &bss, NULL, NULL) < 0) {
		fprintf(stderr, "Get bssinfo failed!\n");
		return -1;
	}

	if (bss.channel)
		res = bss.channel;
	else {
		//wireless function off!!
	}

	return res;
}

static int valid_chan(int ch, int zz, int width)
{
	int zoneA[] = { 36, 40, 44, 48 };
	int zoneB[] = { 52, 56, 60, 64 };
	int zoneC[] = { 100, 104, 108, 112, 116, 120, 124 };
	int zoneD[] = { 149, 153, 157, 161 };
	int i, find = 0;

	if (zz & 0x08) {
		for (i = 0; i < sizeof(zoneA) / sizeof(int) && find == 0; i++) {
			if (ch == zoneA[i]) {
				if ((i % 2) == 0)
					find = 1;
				else
					find = 2;
			}
		}
	}
	if (zz & 0x04) {
		for (i = 0; i < sizeof(zoneB) / sizeof(int) && find == 0; i++) {
			if (ch == zoneB[i]) {
				if ((i % 2) == 0)
					find = 1;
				else
					find = 2;
			}
		}
	}
	if (zz & 0x02) {
		int size = 7;

		if (width == 1)			//40MHz
			size = 6;
		else if (width == 2)	//80MHz
			size = 4;

		for (i = 0; i < size && find == 0; i++) {
			if (ch == zoneC[i]) {
				if ((i % 2) == 0)
					find = 1;
				else
					find = 2;
			}
		}
	}

	if (zz & 0x01) {
		for (i = 0; i < sizeof(zoneD) / sizeof(int) && find == 0; i++) {
			if (ch == zoneD[i]) {
				if ((i % 2) == 0)
					find = 1;
				else
					find = 2;
			}
		}
	}
	return find;
}

//APACRTL-404
int set_wifi_chan(int res, int idx)
{
	char filename[64] = {0, };

	snprintf(filename, sizeof(filename), "/tmp/cwmp/.wlan%d_ch", idx);
	unlink(filename);

	if (!check_wifi_chan(idx, res))
		return 0;

	yecho(filename, "%d", res);

	return 1;
}

int get_5g_chann_zone(char *val, int bufsz, int idx, int subidx)
{
	char buf[8] = {0, };
#if 0
	int zone = atoi(nvram_safe_get_r("WLAN0_zone", buf, sizeof(buf)));

	if (zone == 0) {
		snprintf(val, bufsz, "%s", "15");
		zone = 15;
	} else
		snprintf(val, bufsz, "%d", zone);

	return zone;
#else
	if (nvram_get_r("WLAN0_zone", buf, sizeof(buf)) != NULL)
		snprintf(val, bufsz, "%s", buf);
	else
		val[0] = '\0';

	return 0;
#endif
}

//APACRTL-404
int set_5g_chann_zone(char *val, int idx, int subidx)
{
	char filename[64] = {0, };

	snprintf(filename, sizeof(filename), "/tmp/cwmp/.wlan%d_band", idx);
	unlink(filename);

	if (STRLEN(val) == 0)
		return 0;

	yecho(filename, "%s", val);

	return 1;
}

int get_wifi_power(int idx)
{
	char tmp[32] = {0, };
	int power_scale = 0;

	snprintf(tmp, sizeof(tmp), "WLAN%d_RFPOWER_SCALE", idx);
	power_scale = nvram_atoi(tmp, 0);

	return 100 - ((power_scale % 4) * 25);
}

int set_wifi_power(int val, int idx)
{
	char tmp[32] = {0, };
	char power_scale[4] = {0, };

	if (val != 25 && val != 50 && val != 75 && val != 100)
		return -9007;

	snprintf(tmp, sizeof(tmp), "WLAN%d_RFPOWER_SCALE", idx);
	snprintf(power_scale, sizeof(power_scale), "%d", (100 - val) % 4);
	nvram_set(tmp, power_scale);

	return 1;
}

int get_wifi_radio_status(int idx)
{
	char tmp[32] = {0, };

	snprintf(tmp, sizeof(tmp), "WLAN%d_WLAN_DISABLED", idx);

	return nvram_atoi(tmp, 0) ? 0 : 1;
}

/*-----------------------------------------------------------------------------
 *  Neighbor AP
 *-----------------------------------------------------------------------------*/

int update_neigh_ap(int radio)
{
	struct sysinfo info;
	int uptime = 0;
	int ret = 0;

	if (radio < 0 || radio >= MAXIDX)
		return 0;

	sysinfo(&info);
	uptime = info.uptime;

	if (uptime > neigh_ap_scanned_time[radio] + 20 || neigh_ap_scanned_time[radio] == 0) {
		ret = scan_neigh_ap(radio);
		neigh_ap_scanned_time[radio] = uptime;
	}

	if (ret < 0)
		return 0;

	return 1;
}

void reset_neigh_ap(int radio)
{
	if (radio < 0 || radio >= MAXIDX)
		return;

	memset(neigh_ap[radio], 0, sizeof(_neighap_info_t) * 128);
	neigh_ap_num[radio] = 0;
}

int scan_neigh_ap(int radio)
{
	char WLAN_IF[20] = {0, };
	int i = 0;
	BssDscr *pBss = NULL;
	int status_cnt = 0;
	int wait_time = 0;
	unsigned char res;
	SS_STATUS_Tp pStatus = NULL;
	SS_STATUS_T tStatus;

	if (radio < 0 || radio >= MAXIDX)
		return -1;

	snprintf(WLAN_IF, sizeof(WLAN_IF), "wlan%d", radio % 2);
	pStatus = &tStatus;
	memset((void *)pStatus, 0,  sizeof(SS_STATUS_T));

	if (STRNCMP(WLAN_IF, "wlan1") != 0 && STRNCMP(WLAN_IF, "wlan0") != 0) {
		return -1;
	}

	while (1) {
		if (getWlSiteSurveyRequest(WLAN_IF, &status_cnt) == -1) {
			fprintf(stderr, "%s - AP Scan : Read site-survey status failed!\n", __FILE__);
		}
		if (status_cnt != 0) {	// not ready
			if (wait_time++ > 15) {
				fprintf(stderr, "%s - AP Scan : scan request timeout!\n", __FILE__);
				return -1;
			}
#ifdef CONFIG_RTK_MESH
			// ==== modified by GANTOE for site survey 2008/12/26 ====
			usleep(1000000 + (rand() % 2000000));
#else
			sleep(1);
#endif
		} else {
			break;
		}
	}

	wait_time = 0;

	while (1) {
		pStatus->number = 1;
		if (getWlSiteSurveyResult(WLAN_IF, pStatus) < 0) {
			fprintf(stderr, "%s - AP Scan : Read site-survey status failed!\n", __FILE__);
			return -1;
		}

		res = pStatus->number;
		memset((void *)pStatus, 0,  sizeof(SS_STATUS_T));

		if (res == 0xff) {   // in progress
#if (defined(CONFIG_RTL_92D_SUPPORT) && defined (CONFIG_POCKET_ROUTER_SUPPORT)) || defined(CONFIG_RTL_DFS_SUPPORT)
			/*prolong wait time due to scan both 2.4G and 5G */
			if (wait_time++ > 20)
#else
			if (wait_time++ > 20)
#endif
			{
				fprintf(stderr, "%s - AP Scan : scan timeout!\n", __FILE__);
				return -1;
			}
			sleep(1);
		} else {
			break;
		}
	}

	//pStatus->number = 0; // request BSS DB
	memset((void *)pStatus, 0,  sizeof(SS_STATUS_T));

	if (getWlSiteSurveyResult(WLAN_IF, pStatus) < 0)
		return -1;

	reset_neigh_ap(radio);

	for (i = 0; i < pStatus->number && pStatus->number != 0xff; i++) {
		pBss = &pStatus->bssdb[i];

		if (!pBss)
			continue;

		neigh_ap[radio][i].channel = pBss->channel;
		neigh_ap[radio][i].rssi = CONV_TO_RSSI(pBss->rssi);
		neigh_ap[radio][i].scan = 1;

		if (radio == 1) {	//2.4MHz
			if ((pBss->t_stamp[1] & (BIT(1) | BIT(2))) == (BIT(1) | BIT(2))) {	//40HMz BELOW
				snprintf(neigh_ap[radio][i].ch_str, NEIGH_CH_STR_LEN, "%d+%d", pBss->channel - 4, pBss->channel);
			} else if ((pBss->t_stamp[1] & (BIT(1) | BIT(2))) == BIT(1)) {		//40MHz ABOVE
				snprintf(neigh_ap[radio][i].ch_str, NEIGH_CH_STR_LEN, "%d+%d", pBss->channel, pBss->channel + 4);
			} else {	//20MHz
				snprintf(neigh_ap[radio][i].ch_str, NEIGH_CH_STR_LEN, "%d", pBss->channel);
			}
		} else {		//5GHz
			if ((pBss->t_stamp[1] & (BSS_BW_MASK << BSS_BW_SHIFT)) == (HT_CHANNEL_WIDTH_80 << BSS_BW_SHIFT)) {	//80MHz
				snprintf(neigh_ap[radio][i].ch_str, NEIGH_CH_STR_LEN, "%d/80", pBss->channel);
			} else if ((pBss->t_stamp[1] & (BIT(1) | BIT(2))) == (BIT(1) | BIT(2))) {	//40HMz BELOW
				snprintf(neigh_ap[radio][i].ch_str, NEIGH_CH_STR_LEN, "%d/40", pBss->channel);
			} else if ((pBss->t_stamp[1] & (BIT(1) | BIT(2))) == BIT(1)) {				//40MHz ABOVE
				snprintf(neigh_ap[radio][i].ch_str, NEIGH_CH_STR_LEN, "%d/40", pBss->channel);
			} else {	//20MHz
				snprintf(neigh_ap[radio][i].ch_str, NEIGH_CH_STR_LEN, "%d", pBss->channel);
			}
		}
	}

	neigh_ap_num[radio] = i;

	return neigh_ap_num[radio];
}

int get_neigh_ap_num(int radio)
{
	if (radio < 0 || radio >= MAXIDX)
		return 0;

	return neigh_ap_num[radio];
}

int get_neigh_ap_channel(int radio, int idx)
{
	if (radio < 0 || radio >= MAXIDX)
		return 0;

	if (idx < 0 || idx >= 128)
		return 0;

	if (neigh_ap[radio][idx].scan == 0)
		return 0;

	return neigh_ap[radio][idx].channel;
}

int get_neigh_ap_rssi(int radio, int idx)
{
	if (radio < 0 || radio >= MAXIDX)
		return 0;

	if (idx < 0 || idx >= 128)
		return 0;

	if (neigh_ap[radio][idx].scan == 0)
		return 0;

	return neigh_ap[radio][idx].rssi;
}

char *get_neigh_ap_qms(char *buf, int bufsz, int radio)
{
	int i = 0;
	int len = 0;
	int bestch = 0;
	char fname[64] = {0, };
	char val[64] = {0, };
	FILE *fp = NULL;

	if (!buf || bufsz <= 10)	//min length : 10(bestch,100)
		return NULL;

	if (radio < 0 || radio >= MAXIDX)
		return NULL;

	snprintf(fname, sizeof(fname), "/proc/dv_wlan%d/dv_best_channel", radio);
	fp = fopen(fname, "r");
	if (!fp)
		return NULL;

	if (!fgets(val, sizeof(val), fp))
		return NULL;

	bestch = atoi(val);
	if (!check_wifi_chan(radio, bestch))
		return NULL;

	len = snprintf(buf, bufsz, "bestch,%d", bestch);

	for (i = 0; i < 128; i++) {
		if (neigh_ap[radio][i].scan == 1) {
			len += snprintf(buf + len, bufsz - len, "|ch%s,%d",
			                neigh_ap[radio][i].ch_str, neigh_ap[radio][i].rssi);
		}
	}

	return buf;
}

char *get_upgrade_time_str(char *val, int bufsz)
{
	int len = 0;
	char upgrade_time[32] = {0, };

	if (!val)
		return NULL;

	nvram_safe_get_r("dv_acs_update_time", upgrade_time, sizeof(upgrade_time));
	len = STRLEN(upgrade_time);

	strncpy(val, upgrade_time, len);
	val[len] = '\0';

	return val;
}

time_t get_upgrade_time()
{
	char t[32] = {0, };
	struct tm up;
	int year = 1970, month = 0, day = 1, hour = 0, min = 0;

	nvram_safe_get_r("dv_acs_update_time", t, sizeof(t));
	if (sscanf(t, "%04d%02d%02d%02d%02d", &year, &month, &day, &hour, &min) != 5)
		return 0;

	memset(&up, 0, sizeof(up));
	up.tm_year = year - 1900;
	up.tm_mon = month - 1;
	up.tm_mday = day;
	up.tm_hour = hour;
	up.tm_min = min;
	return (mktime(&up));
}

void get_polling_list(char *val, int bufsz, int idx, int subidx)
{
	nvram_safe_get_r("dv_acs_polling_list", val, MIN(bufsz, 80));
}

char *get_lan_error(char *val, int bufsz, int idx, int subidx)
{
	snprintf(val, bufsz, "%s", "0");
	val[1] = '\0';
	return val;
}

int set_lan_err_ini(char *val, int idx, int subidx)
{
	return 0;
}

#define FIRST_ERROR "-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1"
#define PORTMON_FILE "/tmp/.portmon_cli_status_tr"
#define PORTMON_GETTIME "/tmp/.portmon_gettime"
int get_err_cnt(char *val, int bufsz, int port, int isTx)
{
	int uptime = 0;
	int gettime = 0;
	int pn = 0;
	int chk = 0;
	char buf[256] = {0, };
	char err[256] = {0, };
	struct sysinfo info;
	FILE *fp = NULL;

	sysinfo(&info);
	uptime = info.uptime;

	if (access(PORTMON_GETTIME, F_OK) == 0) {
		if (yfcat(PORTMON_GETTIME, "%d", &gettime) > 0) {
			if (gettime < 0) {
				gettime = 0;
			}
		}
	} else {
		gettime = 0;
	}

	if (access(PORTMON_FILE, F_OK) != 0 || uptime > gettime + 3 || uptime < gettime) {
		yexecl(NULL, "portmon tr_stat");
		yfecho(PORTMON_GETTIME, O_WRONLY | O_CREAT | O_TRUNC, 0644, "%d", uptime);
	}

	fp = fopen(PORTMON_FILE, "r");
	if (fp == NULL) {
		snprintf(val, bufsz, "%s", FIRST_ERROR);
		return 0;
	}

	if (fgets(buf, sizeof(buf), fp) == NULL) {
		fclose(fp);
		snprintf(val, bufsz, "%s", FIRST_ERROR);
		return 0;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		if (buf[STRLEN(buf) - 1] == '\n') {
			buf[STRLEN(buf) - 1] = '\0';
		}

		if (chk == 0) {
			if ((isTx && nv_strcmp(buf, "tx_err") == 0) || (!isTx && nv_strcmp(buf, "rx_err") == 0)) {
				chk = 1;
			}
			continue;
		}

		sscanf(buf, "%d: %255s", &pn, err);
		if (pn == port) {
			fclose(fp);
			snprintf(val, bufsz, "%s", err);
			return 1;
		} else {
			continue;
		}
	}

	fclose(fp);
	snprintf(val, bufsz, "%s", FIRST_ERROR);
	return 0;
}

//GAPD-7100
//LAN1 MO 1 -> System 0
//LAN2 MO 2 -> System 1
//LAN3 MO 3 -> System 2
//LAN4 MO 4 -> System 3
//WAN       -> System 4
int get_lan_err_cnt_tx(char *val, int bufsz, int portnum)
{
	int port = get_lan_port_num_from_idx(portnum);

	if (port < MIN_PORT || port >= MAX_PORT)
		return 0;

	return get_err_cnt(val, bufsz, port, 1);
}

int get_lan_err_cnt_rx(char *val, int bufsz, int portnum)
{
	int port = get_lan_port_num_from_idx(portnum);

	if (port < MIN_PORT || port >= MAX_PORT)
		return 0;

	return get_err_cnt(val, bufsz, port, 0);
}

int get_wan_err_cnt_tx(char *val, int bufsz)
{
	return get_err_cnt(val, bufsz, WAN_PORT, 1);
}

int get_wan_err_cnt_rx(char *val, int bufsz)
{
	return get_err_cnt(val, bufsz, WAN_PORT, 0);
}


int ip_concat_with_colon(char *val, char *arg, int bufsz)
{
	char *p = NULL;

	if (arg == NULL || STRLEN(arg) < 7)
		return -1;

	p = strstr(val, arg);
	if (p) {	//Find!
		if ((STRLEN(p) == STRLEN(val)) && (*(p + STRLEN(arg)) == ':'))	//First
			return 0;

		if ((*(p - 1) == ':') && (*(p + STRLEN(arg)) == ':'))	//Not First
			return 0;
	}
	snprintf(&val[STRLEN(val)], bufsz - STRLEN(val) - 1, "%s:", arg);

	return 1;
}

#define IGMP_LIST "/tmp/cwmp/.igmp_list"
#define IGMP_TEST_COMMAND "/tmp/cwmp/.igmp_test_cmd"
#define IGMP_TEST_RESULT "/tmp/cwmp/.igmp_test_rst"
int get_igmp_tables(char *val, int bufsz)
{
	FILE *fp = NULL;
	struct in_addr ip;
	char line[256] = "";
	char *args[6];
	int res = 0;
	char needle[24] = "";
	int bufidx = 0;
	int count = 0;

	if (val == NULL || bufsz < 1)
		return -1;

	unlink(IGMP_LIST);

	yexecl(">"IGMP_LIST, "igmp_show");
	fp = fopen(IGMP_LIST, "r");
	if (fp == NULL) {
		val[0] = '\0';
		return -1;
	}

	//No  Group Address   Ports   Uptime   Expires  Last Reporter
	if (fgets(line, sizeof(line), fp) == NULL) {
		fclose(fp);
		unlink(IGMP_LIST);
		val[0] = '\0';
		return -1;
	}

	//--- --------------- ------- -------- -------- ---------------
	if (fgets(line, sizeof(line), fp) == NULL) {
		fclose(fp);
		unlink(IGMP_LIST);
		val[0] = '\0';
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		res = ystrargs(line, args, _countof(args), " \t\r\n", 0);
		if (res == 6 && args[1] != NULL && inet_aton(args[1], &ip)) {
			if (++count == 1) {
				bufidx = snprintf(val, bufsz, ":%s:", args[1]);
			} else {
				snprintf(needle, sizeof(needle), ":%s:", args[1]);
				if (strstr(val, needle) == NULL) {
					bufidx += snprintf(val + bufidx, bufsz - bufidx, "%s:", args[1]);
				}
			}
		}
	}

	if (bufidx > 1) {
		memmove(&val[0], &val[1], bufidx - 1);
		val[bufidx - 2] = '\0';
	} else {
		val[0] = '\0';
	}

	fclose(fp);
	unlink(IGMP_LIST);

	return 1;
}

int get_igmp_test(char *val, int bufsz)
{
	FILE *fp = NULL;

	if (!val || bufsz == 0)
		return -1;

	fp = fopen(IGMP_TEST_COMMAND, "r");
	if (fp) {	//Tested
		if (fgets(val, bufsz, fp)) {	//Test: Not Problem
			ydespaces(val);
			fclose(fp);
			unlink(IGMP_TEST_COMMAND);
			return 1;
		} else {	//Test: Problem!!!
			fclose(fp);
			unlink(IGMP_TEST_COMMAND);
			return -1;
		}
	} else	//Not tested yet
		return 0;
}

int check_number(char *buf)
{
	char *p;

	if (buf == NULL)
		return -1;

	p = buf;
	while (*p) {
		if (isdigit(*p) == 0)
			return -1;
		p++;
	}

	return 1;
}

int set_igmp_test(char *val, int bufsz)
{
	int i = 0;
	int ip[4] = {0, };
	char port[8] = {0, };
	char str[64] = {0, };
	FILE *fp = NULL;

	unlink(IGMP_TEST_COMMAND);
	unlink(IGMP_TEST_RESULT);
	if (!val || bufsz == 0)
		return -1;

	if (STRNCASECMP(val, "test_hd") == 0) {
		snprintf(str, sizeof(str), "igmp_send test_hd");
	} else if (STRNCASECMP(val, "test_sd") == 0) {
		snprintf(str, sizeof(str), "igmp_send test_sd");
	} else if (sscanf(val, "%d.%d.%d.%d/%07s", &ip[0], &ip[1], &ip[2], &ip[3], port) == 5) {
		//IP check
		for (i = 0; i < 4; i++) {
			if (ip[i] < 0 || ip[i] > 255)
				return -1;
		}
		//Port Check
		if (check_number(port) < 0 || (atoi(port) < 0 || atoi(port) > 65535))
			return -1;

		snprintf(str, sizeof(str), "igmp_send %d.%d.%d.%d %s", ip[0], ip[1], ip[2], ip[3], port);
	} else {
		return -1;
	}
	yexecl("> /tmp/cwmp/.igmp_test_rst", str);

	fp = fopen(IGMP_TEST_COMMAND, "w");
	if (!fp) {
		unlink(IGMP_TEST_RESULT);
		return -1;
	}
	fprintf(fp, "%s", val);
	fclose(fp);

	return 1;
}

int get_igmp_test_result(char *val, int bufsz)
{
	char buf[16] = {0, };
	FILE *fp = NULL;

	if (!val || bufsz == 0)
		return -1;

	fp = fopen(IGMP_TEST_RESULT, "r");
	if (fp) {	//Tested
		if (fgets(buf, sizeof(buf), fp)) {	//Test: Not Problem
			ydespaces(buf);
			fclose(fp);
			unlink(IGMP_TEST_RESULT);
		} else {	//Test: Problem!!!
			fclose(fp);
			unlink(IGMP_TEST_RESULT);
			return -1;
		}
	} else	//Not tested yet
		return 0;

	if (STRNCASECMP(buf, "FAIL") == 0)
		snprintf(val, bufsz, "0");
	else if (STRNCASECMP(buf, "SUCCESS") == 0)
		snprintf(val, bufsz, "1");
	else if (STRNCASECMP(buf, "ABORT") == 0)
		snprintf(val, bufsz, "2");
	else {
		unlink(IGMP_TEST_RESULT);
		return -1;
	}

	return 1;
}

int set_default(char *val, int idx, int subidx)
{
#if 0
	if (!nv_strcmp(val, "1")) {
		nvram_set("restore_defaults", "1");
#ifdef LGU_ALLJOYN
		eval("/usr/sbin/dlg2cmd", "DLG", "clear");
#endif
		return 1;
	}
	return 0;
#endif
	return 0;
}

int set_wan_reset(int val)
{
	if (val == 1)
		yexecl_safe("2>/dev/null", "phyconfig %d reset", WAN_PORT);

	return 0;
}

int set_lan_reset(int val, int idx, int subidx)
{
	if (val == 1) {
#if 0
		char *p = NULL;
		if (idx == 0)
			p = strchr(DEV_PHYPNM, 'W');
		else
			p = strchr(DEV_PHYPNM, '0' + idx);
		if (p)
			yexecl("2>/dev/null", "phyconfig %d reset", (int)(p - DEV_PHYPNM));
#endif
		/*
			idx 1-4 : LAN1- LAN4
			phyconfig (0~3) reset;
		*/

		yexecl("2>/dev/null", "phyconfig %d reset", idx - 1);
	}

	return 0;
}

int set_wifi_reset(int val, int idx, int subidx)
{
	char prefix[16] = {0, };

	if (val != 1)
		return 0;

	get_wlan_ifname_from_idx(prefix, 16, idx, -1);

	yexecl_safe(NULL, "/usr/sbin/wl -i %s down", prefix);
	sleep(2);
	yexecl_safe(NULL, "/usr/sbin/wl -i %s up", prefix);

#if 0
#if defined(__WBRIDGE__)
	wbr_bss_start(idx, NULL);
#endif
#endif

	return 0;
}

int get_remote_http(char *val, int bufsz, int idx, int subidx)
{
	char buf[8] = "", *p = NULL;

	p = nvram_get_r("WEB_WAN_ACCESS_ENABLED", buf, sizeof(buf));
	if (p != NULL) {
		snprintf(val, bufsz, "%s", p);
		val[1] = '\0';
	} else
		snprintf(val, bufsz, "%s", "0");

	return atoi(val);
}

int set_remote_http(char *val, int idx, int subidx)
{
	char dfl_passwd[32] = {0, };

	//APACRTL-405
	if (STRLEN(val) == 0 ||
	    ((STRLEN(val) > 0) && ((strncmp(val, "0", 1) != 0) && (strncmp(val, "1", 1) != 0))))
		return 0;

	lgu_default_val(LGU_DEF_WEB_PASS, dfl_passwd, sizeof(dfl_passwd));

	if ((val[0] == '1') && nvram_match("http_passwd", dfl_passwd))
		return 0;

	if (!nvram_match("WEB_WAN_ACCESS_ENABLED", val))
		yecho("/tmp/change_remote", "%d", atoi(val));

	nvram_set("WEB_WAN_ACCESS_ENABLED", val);

	return 1;
}

char *get_remote_http_ip(char *val, int bufsz, int idx, int subidx)
{
	if (!val)
		return NULL;

	nvram_safe_get_r("http_remote_access_ip", val, MIN(bufsz, 80));

	return val;
}

int set_remote_http_ip(char *val, int idx, int subidx)
{
	struct in_addr ip;

	if (STRLEN(val) == 0 || inet_aton(val, &ip) == 0)
		return 0;

	nvram_set("http_remote_access_ip", val);

	return 1;
}

int get_remote_http_port(char *val, int bufsz, int idx, int subidx)
{
	char buf[8] = {0, }, *p = NULL;

	p = nvram_get_r("http_remote_access_port", buf, sizeof(buf));

	if (p != NULL)
		snprintf(val, bufsz, "%s", p);
	else
		snprintf(val, bufsz, "%s", "0");

	return atoi(val);
}

int set_remote_http_port(char *val, int idx, int subidx)
{
	char *end;
	int var = strtol(val, &end, 10);

	if (STRLEN(val) == 0 || STRLEN(end) > 0 || var <= 0 || var > 65535)
		return 0;

	nvram_set("http_remote_access_port", val);

	return 1;
}

int get_dm_reg_use(char *val, int bufsz, int idx, int subidx)
{
	//get_dm_reg_use is not used.
	//Only for reporting data.(QMS)
	if (!val)
		return 0;

	if (nvram_match_r("ipdm_regval_use", "1"))
		snprintf(val, bufsz, "%s", "1");
	else
		snprintf(val, bufsz, "%s", "0");

	return atoi(val);
}

int set_dm_reg_use(char *val, int idx, int subidx)
{
	//set_dm_reg_use is not used.
#if 0
	if (STRLEN(val) == 0 || (nv_strcmp(val, "0") && nv_strcmp(val, "1")))
		return 0;
	if (nvram_match_r("ipdm_regval_use", val))
		return 0;
	nvram_set("ipdm_regval_use", val);
	return 1;
#endif
	return 0;
}

int get_dm_reg_period(char *val, int bufsz, int idx, int subidx)
{
	//get_dm_reg_period is not used.
	//Only for reporting data.(QMS)
	char buf[32] = {0, }, *p;

	p = nvram_get_r("ipdm_reg_period", buf, sizeof(buf));
	if (p != NULL && p[0])
		snprintf(val, bufsz, "%s", p);
	else
		snprintf(val, bufsz, "%s", "3600");

	return atoi(val);
}

int set_dm_reg_period(char *val, int idx, int subidx)
{
	//set_dm_reg_period is not used.
#if 0
	char *end;
	int res;

	res = strtol(val, &end, 10);
	if (STRLEN(val) == 0 || STRLEN(end) > 0 || res < 0)
		return 0;

	nvram_set("ipdm_reg_period", val);
	return 1;
#endif

	return 0;
}

int get_dm_hp_period(char *val, int bufsz, int idx, int subidx)
{
	if (!val)
		return -1;

	nvram_safe_get_r("ipdm_hp_period", val, bufsz);
	return atoi(val);
}

int set_dm_hp_period(char *val, int idx, int subidx)
{
	char *end;
	int res;

	res = strtol(val, &end, 10);
	if (STRLEN(val) == 0 || STRLEN(end) > 0 || res < 0)
		return 0;

	nvram_set("ipdm_hp_period", val);
	return 1;
}

int get_dm_hp_ttl(char *val, int bufsz, int idx, int subidx)
{
	if (!val)
		return -1;

	nvram_safe_get_r("ipdm_hp_ttl", val, bufsz);
	return atoi(val);
}

int set_dm_hp_ttl(char *val, int idx, int subidx)
{
	char *end = NULL;
	int res = 0;

	res = strtol(val, &end, 10);
	if (STRLEN(val) == 0 || STRLEN(end) > 0 || res < 0)
		return 0;

	nvram_set("ipdm_hp_ttl", val);
	return 1;
}

char *get_root_passwd(char *val, int bufsz, int idx, int subidx)
{
	if (!val)
		return NULL;

	nvram_safe_get_r("http_super_passwd", val, MIN(bufsz, 80));
	return val;
}

int set_root_passwd(char *val, int idx, int subidx)
{
	if (val[0] != 0 && STRLEN(val) < 8)
		return 0;
	nvram_set("http_super_passwd", val);
	if (val[0] != 0 && access("/tmp/http_access_time", F_OK) != 0) {
		yecho("/tmp/http_access_time", "%d", ygettime(NULL));
		yexecl(NULL, "timed_acl web 600");	// APACRTL-154
	}

	//for timed_acl (Do not restart ap services!!)
	return 0;
}

char *get_conf_radius_domain(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	memset(tmp, 0, sizeof(tmp));

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_RS_DOMAIN", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_RS_DOMAIN", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;

}

char *get_conf_radius_ip(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_RS_IP", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_RS_IP", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_conf_radius_port(char *val, int bufsz, int idx, int subidx)
{
	char tmp[8] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_RS_PORT", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_RS_PORT", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_conf_radius_domain2(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_RS2_DOMAIN", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_RS2_DOMAIN", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_conf_radius_ip2(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_RS2_IP", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_RS2_IP", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_conf_radius_port2(char *val, int bufsz, int idx, int subidx)
{
	char tmp[8] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_RS2_PORT", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_RS2_PORT", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_conf_acct_domain(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_ACCOUNT_RS_DOMAIN", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_ACCOUNT_RS_DOMAIN", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_conf_acct_ip(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_ACCOUNT_RS_IP", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_ACCOUNT_RS_IP", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_conf_acct_port(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_ACCOUNT_RS_PORT", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_ACCOUNT_RS_PORT", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_conf_acct_domain2(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_ACCOUNT_RS2_DOMAIN", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_ACCOUNT_RS2_DOMAIN", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_conf_acct_ip2(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_ACCOUNT_RS2_IP", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_ACCOUNT_RS2_IP", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_conf_acct_port2(char *val, int bufsz, int idx, int subidx)
{
	char tmp[8] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	if (idx == 0)
		nvram_safe_get_r("acs_mbr_ACCOUNT_RS2_PORT", tmp, sizeof(tmp));
	else if (idx == 1)
		nvram_safe_get_r("acs_spc_ACCOUNT_RS2_PORT", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_qms_domain(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	nvram_safe_get_r("dv_qms_server", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_qms_ip(char *val, int bufsz, int idx, int subidx)
{
	char tmp[128] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	nvram_safe_get_r("dv_qms_ip", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_qms_port1(char *val, int bufsz, int idx, int subidx)
{
	char tmp[8] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	nvram_safe_get_r("dv_qms_port1", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_qms_port2(char *val, int bufsz, int idx, int subidx)
{
	char tmp[8] = {0, };
	int len = 0;

	if (!val)
		return NULL;

	nvram_safe_get_r("dv_qms_port2", tmp, sizeof(tmp));

	len = STRLEN(tmp);
	if (len > 0) {
		strncpy(val, tmp, len);
		val[len] = '\0';
	} else {
		val[0] = '\0';
	}

	return val;
}

char *get_shared_secret(char *val, int bufsz, int idx, int subidx)
{
	if (!val)
		return NULL;

	if (nvram_match_r("radius_key_manual", "1"))
		nvram_safe_get_r("radius_key", val, MIN(bufsz, 80));
	else {
		FILE *fp;

		fp = fopen("/tmp/rad_ssecret", "r");
		if (fp) {
			fgets(val, MIN(bufsz, 80), fp);
			fclose(fp);
		}
	}

	return val;
}

int set_shared_secret(char *val, int idx, int subidx)
{
	if (STRLEN(val) == 0)
		return 0;

	nvram_set("radius_key", val);

	return 1;
}

int get_shared_secret_flag()
{
	if (nvram_match_r("radius_key_manual", "1"))
		return 1;

	return 0;
}

int set_shared_secret_flag(int res, int idx, int subidx)
{
	char val[4] = {0, };

	if (res != 0 && res != 1)
		return 0;

	snprintf(val, sizeof(val), "%d", res + 1);
	nvram_set("radius_key_manual", val);
	return 1;
}

int get_conf_web_auth_port(int idx, int subidx)
{
	char buf[8] = {0, };

	nvram_safe_get_r("acs_web_auth_port", buf, sizeof(buf));

	return (atoi(buf));
}

char *get_auth_web_redir_url(char *val, int bufsz, int idx, int subidx)
{
	char *p, buf[128] = {0, };

	val[0] = 0;
	p = nvram_get_r("x_ACS_LGAUTH_WEB_REDIRECT_URL", buf, sizeof(buf));
	if (p != NULL) {
		if ((p = strstr(buf, "http://")) != NULL) {
			p += STRLEN("http://");
			snprintf(val, bufsz, "%s", p);
		} else {
			snprintf(val, bufsz, "%s", buf);
		}
	}

	return val;
}

int set_auth_web_redir_url(char *val, int idx, int subidx)
{
	char *p, buf[128] = {0, }, t[128] = {0, };

	p = strstr(val, "http://");
	if (p != NULL)
		snprintf(buf, sizeof(buf), "%s", val);
	else
		snprintf(buf, sizeof(buf), "http://%s", val);

	if (nv_strcmp(buf, nvram_safe_get_r("x_ACS_LGAUTH_WEB_REDIRECT_URL", t, sizeof(t))) != 0) {
		nvram_set("x_ACS_LGAUTH_WEB_REDIRECT_URL", buf);
		return 1;
	}
	return 0;
}

char *get_first_window(char *val, int bufsz, int idx, int subidx)
{
	char key[32] = {0, }, t[8] = {0, };
	int  res;

	if (subidx >= 0)
		snprintf(key, sizeof(key), "WLAN%d.VAP%d_dv_fwindow", idx, subidx);
	else if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_dv_fwindow", idx);

	res = atoi(nvram_safe_get_r(key, t, sizeof(t)));
	snprintf(val, bufsz, "%d", res);

	return val;
}

char *get_first_window_url(char *val, int bufsz, int idx, int subidx)
{
	char key[32] = {0, };
	char *p, buf[128] = {0, };

	*val = 0;

	if (subidx >= 0)
		snprintf(key, sizeof(key), "WLAN%d.VAP%d_dv_fwindow_url", idx, subidx);
	else if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_dv_fwindow_url", idx);
	else if (subidx == -2)
		snprintf(key, sizeof(key), "%s", "acs_dv_fwindow_url");

	nvram_safe_get_r(key, buf, sizeof(buf));
	if (buf[0] != 0) {
		if ((p = strstr(buf, "http://")) != NULL) {
			p += STRLEN("http://");
			snprintf(val, bufsz, "%s", p);
		} else {
			snprintf(val, bufsz, "%s", buf);
		}
	}

	return val;
}

int get_phy_tx_over(int idx, int subidx)
{
	int res = 0;
	char key[32] = {0, }, buf[8] = {0, };

	if (idx == 1) {
		snprintf(key, sizeof(key), "phy_tx_over%d", idx);
		res = atoi(nvram_safe_get_r(key, buf, sizeof(buf)));
	}

	return res;
}

int set_phy_tx_over(int res, int idx, int subidx)
{
	char key[32] = {0, }, val[8] = {0, };

	if ((res != 0 && res != 1) || idx > 1)
		return 0;
	snprintf(val, sizeof(val), "%d", res);
	snprintf(key, sizeof(key), "phy_tx_over%d", idx);
	nvram_set(key, val);
	return 1;
}

int get_phy_rx_over(int idx, int subidx)
{
	int res = 0;
	char key[32] = {0, }, buf[8] = {0, };

	if (idx == 1) {
		snprintf(key, sizeof(key), "phy_rx_over%d", idx);
		res = atoi(nvram_safe_get_r(key, buf, sizeof(buf)));
	}
	return res;
}

int set_phy_rx_over(int res, int idx, int subidx)
{
	char key[32] = {0, }, val[8] = {0, };

	if ((res != 0 && res != 1) || idx > 1)
		return 0;
	snprintf(val, sizeof(val), "%d", res);
	snprintf(key, sizeof(key), "phy_rx_over%d", idx);
	nvram_set(key, val);
	return 1;
}

int get_phy_tx_th(int idx, int subidx)
{
	int res = 0;
	char key[32] = {0, }, buf[8] = {0, };

	if (idx == 1) {
		snprintf(key, sizeof(key), "phy_tx_th%d", idx);
		res = atoi(nvram_safe_get_r(key, buf, sizeof(buf)));
	}

	return res;
}

int set_phy_tx_th(int res, int idx, int subidx)
{
	char key[32] = {0, }, val[8] = {0, };

	if (res < 0 || idx > 1)
		return 0;
	snprintf(val, sizeof(val), "%d", res);
	snprintf(key, sizeof(key), "phy_tx_th%d", idx);
	nvram_set(key, val);
	return 1;
}

int get_phy_rx_th(int idx, int subidx)
{
	int res = 0;
	char key[32] = {0, }, buf[8] = {0, };

	if (idx == 1) {
		snprintf(key, sizeof(key), "phy_rx_th%d", idx);
		res = atoi(nvram_safe_get_r(key, buf, sizeof(buf)));
	}

	return res;
}

int set_phy_rx_th(int res, int idx, int subidx)
{
	char key[32] = {0, }, val[8] = {0, };

	if (res < 0)
		return 0;
	snprintf(val, sizeof(val), "%d", res);
	snprintf(key, sizeof(key), "phy_rx_th%d", idx);
	nvram_set(key, val);
	return 1;
}

int get_ssid_tx_over(int idx, int subidx)
{
	int res;
	char key[32] = {0, }, buf[8] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_tx_over", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_tx_over", idx, subidx);

	res = atoi(nvram_safe_get_r(key, buf, sizeof(buf)));
	return res;
}

int set_ssid_tx_over(int res, int idx, int subidx)
{
	char key[32] = {0, }, val[8] = {0, };

	if (res != 0 && res != 1)
		return 0;
	snprintf(val, sizeof(val), "%d", res);

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_tx_over", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_tx_over", idx, subidx);

	nvram_set(key, val);
	return 1;
}

int get_ssid_rx_over(int idx, int subidx)
{
	int res;
	char key[32] = {0, }, buf[8] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_rx_over", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_rx_over", idx, subidx);

	res = atoi(nvram_safe_get_r(key, buf, sizeof(buf)));

	return res;
}

int set_ssid_rx_over(int res, int idx, int subidx)
{
	char key[32] = {0, }, val[8] = {0, };

	if (res != 0 && res != 1)
		return 0;

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_rx_over", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_rx_over", idx, subidx);

	snprintf(val, sizeof(val), "%d", res);
	nvram_set(key, val);
	return 1;
}

int get_ssid_tx_th(int idx, int subidx)
{
	int res;
	char key[32] = {0, }, buf[8] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_tx_th", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_tx_th", idx, subidx);

	res = atoi(nvram_safe_get_r(key, buf, sizeof(buf)));
	return res;
}

int set_ssid_tx_th(int res, int idx, int subidx)
{
	char key[32] = {0, }, val[8] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_tx_th", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_tx_th", idx, subidx);

	snprintf(val, sizeof(val), "%d", res);
	nvram_set(key, val);
	return 1;
}

int get_ssid_rx_th(int idx, int subidx)
{
	int res;
	char key[32] = {0, }, buf[8] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_rx_th", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_rx_th", idx, subidx);

	res = atoi(nvram_safe_get_r(key, buf, sizeof(buf)));

	return res;
}

int set_ssid_rx_th(int res, int idx, int subidx)
{
	char key[32] = {0, }, val[8] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_rx_th", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_rx_th", idx, subidx);

	snprintf(val, sizeof(val), "%d", res);
	nvram_set(key, val);
	return 1;
}

int get_ssid_conn_over(int idx, int subidx)
{
	int res;
	char key[32] = {0, }, buf[8] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_assoc_over", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_assoc_over", idx, subidx);

	res = atoi(nvram_safe_get_r(key, buf, sizeof(buf)));
	return res;
}

int set_ssid_conn_over(int res, int idx, int subidx)
{
	char key[32] = {0, }, val[8] = {0, };

	if (res != 0 && res != 1)
		return 0;

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_assoc_over", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_assoc_over", idx, subidx);

	snprintf(val, sizeof(val), "%d", res);
	nvram_set(key, val);
	return 1;
}

int get_ssid_conn_th(int idx, int subidx)
{
	int res;
	char key[32] = {0, }, buf[8] = {0, };

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_assoc_th", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_assoc_th", idx, subidx);

	res = atoi(nvram_safe_get_r(key, buf, sizeof(buf)));
	return res;
}

int set_ssid_conn_th(int res, int idx, int subidx)
{
	char key[32] = {0, }, val[8] = {0, };

	if (res < 0 || res > 128)
		return 0;

	if (subidx == -1)
		snprintf(key, sizeof(key), "WLAN%d_assoc_th", idx);
	else
		snprintf(key, sizeof(key), "WLAN%d_VAP%d_assoc_th", idx, subidx);

	snprintf(val, sizeof(val), "%d", res);
	nvram_set(key, val);
	return 1;
}

void get_white_list_version(char *val, int bufsz, int idx, int subidx)
{
	nvram_safe_get_r("white_list_ver", val, MIN(bufsz, 20));
}

void get_white_list_type(char *val, int bufsz, int idx, int subidx)
{
	nvram_safe_get_r("white_list_type", val, MIN(bufsz, 20));
}

int update_white_list(int res)
{
	if (res == 1)
		yexecl(NULL, "/usr/sbin/update_wlist &");

	return 0;
}

char *get_mon_time(char *val, int bufsz)
{
	if (!val)
		return NULL;

	char *mon_time = nvram_safe_get_r("dv_mon_time", val, bufsz);
	if (*mon_time == 0)
		snprintf(val, bufsz, "%s", "00:00");

	return val;
}

int set_mon_time(char *val)
{
	int hour;
	int min;
	char *endPtr;

	hour = strtol(val, &endPtr, 10);
	if (*endPtr == ':') {
		endPtr++;
		min = atoi(endPtr);
		if ((hour >= 0 && hour < 24) && (min >= 0 && min < 60)) {
			nvram_set("dv_mon_time", val);
			unlink("/var/tmp/cwmp/.tr_report");
			return 1;
		}
	}

	return 0;
}

int get_mon_range(void)
{
	char buf[32] = {0, };
	int range = atoi(nvram_safe_get_r("dv_mon_range", buf, sizeof(buf)));

	return range;
}

int set_mon_range(int res)
{
	char val[8] = {0, };

	if (res < 0 || res > 999)
		return 0;

	snprintf(val, sizeof(val), "%d", res);

	nvram_set("dv_mon_range", val);

	return 1;
}

int get_mon_days(void)
{
	char buf[32] = {0, };

	int period = atoi(nvram_safe_get_r("dv_mon_days", buf, sizeof(buf)));

	return period;
}

int set_mon_days(int res)
{
	char val[8] = {0, };

	if (res < 0 || res > 99)
		return 0;

	snprintf(val, sizeof(val), "%d", res);

	nvram_set("dv_mon_days", val);

	return 1;
}

int get_mon_period(char *val, int bufsz)
{
	char *p = nvram_safe_get_r("dv_mon_period", val, bufsz);

	if (*p == 0)
		snprintf(val, bufsz, "%s", "0");

	return atoi(val);
}

int set_mon_period(char *val)
{
	char *end;
	int res = strtol(val, &end, 10);

	if (STRLEN(val) == 0 || (STRNCASECMP(val, "none") && STRLEN(end) > 0) || res < 0 || res > 99)
		return 0;

	nvram_set("dv_mon_period", val);
	return 1;
}

int get_mon_basic_info(void)
{
	char buf[4] = {0, };

	nvram_get_r("dv_mon_basic_info", buf, sizeof(buf));

	return (atoi(buf));
}

int set_mon_basic_info(int res)
{
	char val[4] = {0, };

	if (res < 0 || res > 2)
		return 0;

	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_mon_basic_info", val);

	return 1;
}

int get_mon_config_info(void)
{
	char buf[4] = {0, };
	char *p = nvram_get_r("dv_mon_config_info", buf, sizeof(buf));

	if (!p)
		p = &buf[0];

	return (atoi(p));
}

int set_mon_config_info(int res)
{
	char val[4] = {0, };
	if (res != 0 && res != 1)
		if (res < 0 || res > 2)
			return 0;

	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_mon_config_info", val);

	return 1;
}

int get_mon_wifi_info(void)
{
	char buf[4] = {0, };
	char *p = nvram_safe_get_r("dv_mon_wifi_info", buf, sizeof(buf));

	if (!p)
		p = &buf[0];

	return (atoi(p));
}

int set_mon_wifi_info(int res)
{
	char val[4] = {0, };

	if (res != 0 && res != 1)
		if (res < 0 || res > 2)
			return 0;

	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_mon_wifi_info", val);

	return 1;
}

int get_mon_wifi5_info(void)
{
	char buf[4] = {0, };
	char *p = nvram_safe_get_r("dv_mon_wifi5_info", buf, sizeof(buf));

	if (!p)
		p = &buf[0];

	return (atoi(p));
}

int set_mon_wifi5_info(int res)
{
	char val[4] = {0, };

	if (res != 0 && res != 1)
		if (res < 0 || res > 2)
			return 0;

	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_mon_wifi5_info", val);

	return 1;
}

int get_mon_qos_info(void)
{
	char buf[4] = {0, };
	nvram_safe_get_r("dv_mon_qos_info", buf, sizeof(buf));

	return (atoi(buf));
}

int set_mon_qos_info(int res)
{
	char val[4] = {0, };

	if (res < 0 || res > 2)
		return 0;

	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_mon_qos_info", val);

	return 1;
}

int get_mon_ipdm_info(void)
{
	char buf[4] = {0, };
	nvram_get_r("dv_mon_ipdm_info", buf, sizeof(buf));

	return (atoi(buf));
}

int set_mon_ipdm_info(int res)
{
	char val[4] = {0, };

	if (res < 0 || res > 2)
		return 0;

	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_mon_ipdm_info", val);

	return 1;
}

int get_mon_server_info(void)
{
	char buf[4] = {0, };
	nvram_get_r("dv_mon_server_info", buf, sizeof(buf));

	return (atoi(buf));
}

int set_mon_server_info(int res)
{
	char val[4] = {0, };

	if (res < 0 || res > 2)
		return 0;

	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_mon_server_info", val);

	return 1;
}

int get_mon_service_info(void)
{
	char buf[4] = {0, };
	nvram_get_r("dv_mon_service_info", buf, sizeof(buf));

	return (atoi(buf));
}

int set_mon_service_info(int res)
{
	char val[4] = {0, };
	if (res < 0 || res > 2)
		return 0;
	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_mon_service_info", val);

	return 0;
}

int get_mon_mon_info(void)
{
	char buf[4] = {0, };
	nvram_safe_get_r("dv_mon_mon_info", buf, sizeof(buf));
	return (atoi(buf));
}

int set_mon_mon_info(int res)
{
	char val[4] = {0, };
	if (res < 0 || res > 2)
		return 0;
	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_mon_mon_info", val);

	return 0;
}

int get_mon_acl_info(void)
{
	char buf[4] = {0, };
	nvram_safe_get_r("dv_mon_acl_info", buf, sizeof(buf));
	return (atoi(buf));
}

int set_mon_acl_info(int res)
{
	char val[4] = {0, };
	if (res < 0 || res > 2)
		return 0;

	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_mon_acl_info", val);

	return 0;
}

int get_traffic_mon(void)
{
	if (nvram_match_r("dv_traffic_mon", "1"))
		return 1;

	return 0;
}

int set_traffic_mon(int res)
{
	char val[4] = {0, };

	if (res != 0 && res != 1)
		return 0;

	snprintf(val, sizeof(val), "%d", res);
	nvram_set("dv_traffic_mon", val);
	return 1;
}

char *get_traffic_time(char *val, int bufsz)
{
	char t[64] = {0, };
	char *ptr = nvram_safe_get_r("dv_traffic_time", t, sizeof(t));

	if (*ptr == 0)
		snprintf(t, sizeof(t), "%s", "00:00");
	strncpy(val, t, bufsz);

	return val;
}

int set_traffic_time(char *val)
{
	int hour;
	int min;
	char *endPtr;

	hour = strtol(val, &endPtr, 10);
	if (*endPtr == ':') {
		endPtr++;
		min = atoi(endPtr);
		if ((hour >= 0 && hour < 24) && (min >= 0 && min < 60)) {
			nvram_set("dv_traffic_time", val);
			unlink("/var/tmp/cwmp/.tr_report");
			return 1;
		}
	}
	return 0;
}

int get_traffic_range(void)
{
	char buf[32] = {0, };
	int range = 0;

	nvram_safe_get_r("dv_traffic_range", buf, sizeof(buf));
	range = atoi(buf);

	return range;
}

int get_filtering_list(struct _packet_filter_t *pf_list)
{
	//nvram name replaced to 7100's
	char key[32] = {0, };
	char tmpStr[160] = {0, };
	char *onOff;
	char *policy;
	char *direction;
	char *priority;
	char *proto;
	char *srcip, *srcport;
	char *dstip;
	char *dstport;
	char *srcinfo, *dstinfo;
	int i;
	char *val;
	int num;
	struct _packet_filter_t *info = pf_list;

	num = atoi(nvram_safe_get_r("packet_filter_max", key, sizeof(key)));
	if (num > 30)
		num = 30;

	for (i = 0; i < num; i++, info++) {
		snprintf(key, sizeof(key), "packet_filter%d", i + 1);	// packet_filter1 ~ packet_filter30
		nvram_safe_get_r(key, tmpStr, sizeof(tmpStr));
		if (tmpStr[0] != 0) {
			val = tmpStr;
			srcinfo = strsep(&val, ",");
			if (!srcinfo)
				continue;
			dstinfo = strsep(&val, ",");
			if (!dstinfo)
				continue;
			proto = strsep(&val, ",");
			if (!proto)
				continue;
			onOff = strsep(&val, ",");
			if (!onOff)
				continue;
			direction = strsep(&val, ",");
			if (!direction)
				continue;
			priority = strsep(&val, ",");
			if (!priority)
				continue;
			policy = val;
			if (!policy || STRLEN(policy) == 0)
				continue;
			/* Format : onoff,policy,direction,protocol,srcip,srcport,srcmac,dstip,dstport,dstmac */
			info->enable = (STRNCASECMP(onOff, "off") == 0) ? 0 : 1;
			if (!STRNCASECMP(policy, "allow"))
				snprintf(info->policy, sizeof(info->policy), "%s", "accept");
			else if (!STRNCASECMP(policy, "deny"))
				snprintf(info->policy, sizeof(info->policy), "%s", "deny");
			if (!STRNCASECMP(direction, "io"))
				snprintf(info->direction, sizeof(info->direction), "%s", "out");
			else if (!STRNCASECMP(direction, "oi"))
				snprintf(info->direction, sizeof(info->direction), "%s", "in");
			if (!STRNCASECMP(proto, "ALL"))
				snprintf(info->protocol, sizeof(info->protocol), "%s", "all");
			else
				snprintf(info->protocol, sizeof(info->protocol), "%s", proto);

			if (strchr(srcinfo, '-') != NULL) {
				srcip = strsep(&srcinfo, ":");
				srcport = srcinfo;
				if (!srcip || !srcport)
					continue;

				snprintf(info->srcip, sizeof(info->srcip), "%s", srcip);
				info->srcmac[0] = 0;
				snprintf(info->srcport, sizeof(info->srcport), "%s", srcport);
#if 0
				if (nv_strcmp(srcip, "0.0.0.0-0.0.0.0") == 0)
					j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "*,");
				else {
					char tmp[40] = {0, }, *s1, *s2;
					s2 = tmp;
					snprintf(tmp, sizeof(tmp), "%s", srcip);
					s1 = strsep(&s2, "-");
					if (inet_addr(s1) == inet_addr(s2))
						j += snprintf(chStr + j, sizeof(chStr) - j, "%s,", s1);
					else
						j += snprintf(chStr + j, sizeof(chStr) - j, "%s,", srcip);
				}
				if (nv_strcmp(srcport, "0-0") == 0)
					j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "*,,");
				else {
					int p1 = -1, p2 = -2;
					sscanf(srcport, "%d-%d", &p1, &p2);
					if (p1 == p2)
						j += snprintf(chStr + j, sizeof(chStr) - j, "%d,,", p1);
					else
						j += snprintf(chStr + j, sizeof(chStr) - j, "%s,,", srcport);
				}
#endif
			} else {
				snprintf(info->srcmac, sizeof(info->srcmac), "%s", srcinfo);
				info->srcip[0] = 0;
				info->srcport[0] = 0;
#if 0
				strncpy(srcmac, srcinfo, sizeof(srcmac));
				j += snprintf(chStr + j, sizeof(chStr) - j, ",,%s,", conv_mac_format(srcmac));
#endif
			}

			dstip = strsep(&dstinfo, ":");
			dstport = dstinfo;
			if (!dstip || !dstport)
				continue;
			snprintf(info->dstip, sizeof(info->dstip), "%s", dstip);
			snprintf(info->dstport, sizeof(info->dstport), "%s", dstport);
#if 0
			if (nv_strcmp(dstip, "0.0.0.0-0.0.0.0") == 0)
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "*,");
			else {
				char tmp[40] = {0, }, *s1, *s2;
				s2 = tmp;
				snprintf(tmp, sizeof(tmp), "%s", dstip);
				s1 = strsep(&s2, "-");
				if (inet_addr(s1) == inet_addr(s2))
					j += snprintf(chStr + j, sizeof(chStr) - j, "%s,", s1);
				else
					j += snprintf(chStr + j, sizeof(chStr) - j, "%s,", dstip);
			}
			if (nv_strcmp(dstport, "0-0") == 0)
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "*,");
			else {
				int p1 = -1, p2 = -2;
				sscanf(dstport, "%d-%d", &p1, &p2);
				if (p1 == p2)
					j += snprintf(chStr + j, sizeof(chStr) - j, "%d,", p1);
				else
					j += snprintf(chStr + j, sizeof(chStr) - j, "%s,", dstport);
			}
			chStr[j] = 0;

			if (len + STRLEN(chStr) >= bufsz)
				break;
			if (len > 0)
				len += snprintf(buf + len, bufsz - len, "%s", "|");
			len += snprintf(buf + len, bufsz - len, "%s", chStr);
#endif
		}
	}
	return num;
}

char *get_filtering_list_qms(char *buf, int bufsz)
{
	//nvram name replaced to 7100's
	char key[32] = {0, };
	char tmpStr[160] = {0, }, chStr[128] = {0, };
	char *onOff;
	char *policy;
	char *direction;
	char *priority;
	char *proto;
	char *srcip, *srcport;
	char srcmac[20] = {0, };
	char *dstip;
	char *dstport;
	char *srcinfo, *dstinfo;
	int len = 0;
	int i = 0, j = 0;
	char *val;
	int num;

	if (!buf)
		return NULL;

	num = atoi(nvram_safe_get_r("packet_filter_max", key, sizeof(key)));
	if (num > 30)
		num = 30;
	else if (num < 1) {
		strncpy(buf, "00", 2);
		buf[2] = '\0';
		return buf;
	}

	for (i = 0; i < num; i++) {
		snprintf(key, sizeof(key), "packet_filter%d", i + 1);	// packet_filter1 ~ packet_filter30
		nvram_safe_get_r(key, tmpStr, sizeof(tmpStr));
		if (tmpStr[0] != 0) {
			val = tmpStr;
			srcinfo = strsep(&val, ",");
			if (!srcinfo)
				continue;
			dstinfo = strsep(&val, ",");
			if (!dstinfo)
				continue;
			proto = strsep(&val, ",");
			if (!proto)
				continue;
			onOff = strsep(&val, ",");
			if (!onOff)
				continue;
			direction = strsep(&val, ",");
			if (!direction)
				continue;
			priority = strsep(&val, ",");
			if (!priority)
				continue;
			policy = val;
			if (!policy || STRLEN(policy) == 0)
				continue;
			/* Format : onoff,policy,direction,protocol,srcip,srcport,srcmac,dstip,dstport,dstmac */
			if (!STRNCASECMP(onOff, "off"))
				j = snprintf(chStr, sizeof(chStr), "%s", "0,");
			else if (!STRNCASECMP(onOff, "on"))
				j = snprintf(chStr, sizeof(chStr), "%s", "1,");

			if (!STRNCASECMP(policy, "allow"))
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "e,");
			else if (!STRNCASECMP(policy, "deny"))
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "d,");

			if (!STRNCASECMP(direction, "io"))
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "o,");
			else if (!STRNCASECMP(direction, "oi"))
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "i,");

			if (!STRNCASECMP(proto, "ALL"))
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "*,");
			else if (!STRNCASECMP(proto, "tcp"))
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "t,");
			else if (!STRNCASECMP(proto, "udp"))
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "u,");

			if (strchr(srcinfo, '-') != NULL) {
				srcip = strsep(&srcinfo, ":");
				srcport = srcinfo;
				if (!srcip || !srcport)
					continue;
#if 0
				snprintf(info->srcip, sizeof(info->srcip), "%s", srcip);
				info->srcmac[0] = 0;
				snprintf(info->srcport, sizeof(info->srcport), "%s", srcport);
#else
				if (nv_strcmp(srcip, "0.0.0.0-0.0.0.0") == 0)
					j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "*,");
				else {
					char tmp[40] = {0, }, *s1, *s2;
					s2 = tmp;
					snprintf(tmp, sizeof(tmp), "%s", srcip);
					s1 = strsep(&s2, "-");
					if (inet_addr(s1) == inet_addr(s2))
						j += snprintf(chStr + j, sizeof(chStr) - j, "%s,", s1);
					else
						j += snprintf(chStr + j, sizeof(chStr) - j, "%s,", srcip);
				}
				if (nv_strcmp(srcport, "0-0") == 0)
					j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "*,,");
				else {
					int p1 = -1, p2 = -2;
					sscanf(srcport, "%d-%d", &p1, &p2);
					if (p1 == p2)
						j += snprintf(chStr + j, sizeof(chStr) - j, "%d,,", p1);
					else
						j += snprintf(chStr + j, sizeof(chStr) - j, "%s,,", srcport);
				}
#endif
			} else {
#if 0
				snprintf(info->srcmac, sizeof(info->srcmac), "%s", srcinfo);
				info->srcip[0] = 0;
				info->srcport[0] = 0;
#else
				strncpy(srcmac, srcinfo, sizeof(srcmac));
				j += snprintf(chStr + j, sizeof(chStr) - j, ",,%s,", conv_mac_format(srcmac));
#endif
			}

			dstip = strsep(&dstinfo, ":");
			dstport = dstinfo;
			if (!dstip || !dstport)
				continue;
#if 0
			snprintf(info->dstip, sizeof(info->dstip), "%s", dstip);
			snprintf(info->dstport, sizeof(info->dstport), "%s", dstport);
#else
			if (nv_strcmp(dstip, "0.0.0.0-0.0.0.0") == 0)
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "*,");
			else {
				char tmp[40] = {0, }, *s1, *s2;
				s2 = tmp;
				snprintf(tmp, sizeof(tmp), "%s", dstip);
				s1 = strsep(&s2, "-");
				if (inet_addr(s1) == inet_addr(s2))
					j += snprintf(chStr + j, sizeof(chStr) - j, "%s,", s1);
				else
					j += snprintf(chStr + j, sizeof(chStr) - j, "%s,", dstip);
			}
			if (nv_strcmp(dstport, "0-0") == 0)
				j += snprintf(chStr + j, sizeof(chStr) - j, "%s", "*,");
			else {
				int p1 = -1, p2 = -2;
				sscanf(dstport, "%d-%d", &p1, &p2);
				if (p1 == p2)
					j += snprintf(chStr + j, sizeof(chStr) - j, "%d,", p1);
				else
					j += snprintf(chStr + j, sizeof(chStr) - j, "%s,", dstport);
			}
			chStr[j] = 0;

			if (len + STRLEN(chStr) >= bufsz)
				break;
			if (len > 0)
				len += snprintf(buf + len, bufsz - len, "%s", "|");
			len += snprintf(buf + len, bufsz - len, "%s", chStr);
#endif
		}
	}

	buf[len] = '\0';

	return buf;
}

int set_traffic_range(int res)
{
	char val[8] = {0, };

	if (res < 0 || res > 999)
		return 0;

	snprintf(val, sizeof(val), "%d", res);

	nvram_set("dv_traffic_range", val);

	unlink("/var/tmp/cwmp/.tr_report");
	return 1;
}

int get_traffic_period(void)
{
	char buf[32] = {0, };

	nvram_safe_get_r("dv_traffic_period", buf, sizeof(buf));

	return atoi(buf);
}

int set_traffic_period(int res)
{
	char val[8] = {0, };

	if (res < 0 || res > 999)
		return 0;

	snprintf(val, sizeof(val), "%d", res);

	nvram_set("dv_traffic_period", val);

	unlink("/var/tmp/cwmp/.tr_report");

	return 1;
}

char *get_acl_list(char *strDest, int bufsz)
{
#if 0
	int vfilter_num;
	int i, len;
	char *ptr;
	char buf[128] = {0, }, strKey[32] = {0, };
	char *strProto, *strPort, *strOn, *strEnable;
	char *destip, port[16] = {0, };
	char protocol = '*';
	char *tok_ptr = NULL;

	memset(strDest, 0, bufsz);
	ptr = nvram_safe_get_r("vfilter_client_max", buf, sizeof(buf));
	vfilter_num = atoi(ptr);
	for (i = 0, len = 0; i < vfilter_num && len < bufsz; i++) {
		snprintf(strKey, sizeof(strKey), "vfilter_client%d", i);
		ptr = nvram_safe_get_r(strKey, buf, sizeof(buf));
		if (ptr[0] == 0)
			continue;

		strPort = STRTOK_R(ptr, ",", &tok_ptr);
		strProto = STRTOK_R(NULL, ",", &tok_ptr);
		strOn = STRTOK_R(NULL, ",", &tok_ptr);
		strEnable = STRTOK_R(NULL, ",", &tok_ptr);
		if (!STRNCASECMP(strProto, "udp"))
			protocol = 'u';
		else if (!STRNCASECMP(strProto, "tcp"))
			protocol = 't';
		else if (!STRNCASECMP(strProto, "all"))
			protocol = '*';
		destip = strsep(&strPort, ":");
		if (strPort == NULL || !nv_strcmp(strPort, "0-0"))
			snprintf(port, sizeof(port), "%s", "*");
		else
			snprintf(port, sizeof(port), "%s", strPort);
		if (len == 0)
			len += snprintf(strDest + len, bufsz - len, "o,%c,*,*,%s,%s,%c", protocol,
			                (destip == NULL || STRLEN(destip) == 0) ? "*" : destip,
			                port, STRNCASECMP(strEnable, "accept") == 0 ? 'e' : 'd');
		else
			len += snprintf(strDest + len, bufsz - len, "|o,%c,*,*,%s,%s,%c", protocol,
			                (destip == NULL || STRLEN(destip) == 0) ? "*" : destip,
			                port, STRNCASECMP(strEnable, "accept") == 0 ? 'e' : 'd');
	}
#endif
	strncpy(strDest, "00", 2);
	strDest[2] = '\0';
	return strDest;
}

char *get_acl_info_use(char *val, int bufsz)
{
	//nvram_safe_get_r("vfilter_client_enable", val, MIN(bufsz, 80));
	strncpy(val, "00", 2);
	val[2] = '\0';
	return val;
}

int set_acl_info_use(char *val, int idx, int subidx)
{
#if 0
	if (STRLEN(val) == 0 || (nv_strcmp(val, "0") != 0 && nv_strcmp(val, "1") != 0))
		return 0;
	nvram_set("vfilter_client_enable", val);
	return 1;
#endif
	return 0;
}

int add_acl_info(char *val, int idx, int subidx)
{
#if 0
	char buf[128] = {0, };
	char protocol[8] = {0, };
	char *p = val;
	char strKey[32] = {0, };
	char strSave[128] = {0, };
	int len = 0, i;
	int num = atoi(nvram_safe_get_r("vfilter_client_max", buf, sizeof(buf)));
	char t[128] = {0, };
	char *tok_ptr = NULL;

	if (val[0] != 'o')
		return 0;	// not support inbound filter
	switch (val[2]) {
	case 'u':
	case 'U':
		snprintf(protocol, sizeof(protocol), "%s", "udp");
		break;
	case 't':
	case 'T':
		snprintf(protocol, sizeof(protocol), "%s", "tcp");
		break;
	default:
		snprintf(protocol, sizeof(protocol), "%s", "all");
		break;
	}
	p = STRTOK_R(p, ",", &tok_ptr);
	for (i = 0; i < 4; i++)
		p = STRTOK_R(NULL, ",", &tok_ptr);

	if (p != NULL && nv_strcmp(p, "*"))
		len = snprintf(buf, sizeof(buf), "%s", p);

	p = STRTOK_R(NULL, ",", &tok_ptr);
	if (p == NULL || !nv_strcmp(p, "*"))
		len += snprintf(buf + len, sizeof(buf) - len, "%s", ":all");
	else
		len += snprintf(buf + len, sizeof(buf) - len, ":%s", p);

	len += snprintf(buf + len, sizeof(buf) - len, ",%s,on", protocol);

	p = STRTOK_R(NULL, ",", &tok_ptr);
	if (p != NULL && !nv_strcmp(p, "e"))
		len += snprintf(buf + len, sizeof(buf) - len, ",%s", "accept");
	else if (p != NULL && !nv_strcmp(p, "d"))
		len += snprintf(buf + len, sizeof(buf) - len, ",%s", "deny");
	else
		return 0;

	if (num > 0) {
		int found = -1;
		char *ptr;
		int i;

		for (i = 0; i < num; i++) {
			snprintf(strKey, sizeof(strKey), "vfilter_client%d", i);
			ptr = nvram_safe_get_r(strKey, t, sizeof(t));
			if (*ptr && nv_strcmp(ptr, buf) == 0) {
				found = i;
				break;
			}
		}
		if (found >= 0)
			return 0;
		snprintf(strKey, sizeof(strKey), "vfilter_client%d", num - 1);
		nvram_safe_get_r(strKey, strSave, sizeof(strSave));
	} else if (num == 0) {
		snprintf(strKey, sizeof(strKey), "vfilter_client%d", num);
		snprintf(strSave, sizeof(strSave), "%s", ":0-0,all,on,deny");
		num++;
	}

	nvram_set(strKey, buf);
	snprintf(strKey, sizeof(strKey), "vfilter_client%d", num);
	nvram_set(strKey, strSave);
	num++;
	snprintf(strSave, sizeof(strSave), "%d", num);
	nvram_set("vfilter_client_max", strSave);

	return 1;
#endif
	return 0;
}

int del_acl_info(char *val, int idx, int subidx)
{
#if 0
	char buf[128] = {0, };
	char protocol[8] = {0, };
	char *p = val;
	char strKey[32] = {0, };
	char strSave[128] = {0, };
	int len = 0, i;
	int found = -1;
	int num = atoi(nvram_safe_get_r("vfilter_client_max", buf, sizeof(buf)));
	char t[128] = {0, };
	char *tok_ptr = NULL;

	if (val[0] != 'o')
		return 0;	// not support inbound filter
	switch (val[2]) {
	case 'u':
	case 'U':
		snprintf(protocol, sizeof(protocol), "%s", "udp");
		break;
	case 't':
	case 'T':
		snprintf(protocol, sizeof(protocol), "%s", "tcp");
		break;
	default:
		snprintf(protocol, sizeof(protocol), "%s", "all");
		break;
	}
	p = STRTOK_R(p, ",", &tok_ptr);
	for (i = 0; i < 4; i++)
		p = STRTOK_R(NULL, ",", &tok_ptr);

	if (p != NULL && nv_strcmp(p, "*"))
		len = snprintf(buf, sizeof(buf), "%s", p);

	p = STRTOK_R(NULL, ",", &tok_ptr);
	if (p == NULL || !nv_strcmp(p, "*"))
		len += snprintf(buf + len, sizeof(buf) - len, "%s", ":all");
	else
		len += snprintf(buf + len, sizeof(buf) - len, ":%s", p);

	len += snprintf(buf + len, sizeof(buf) - len, ",%s,on", protocol);

	p = STRTOK_R(NULL, ",", &tok_ptr);
	if (p != NULL && !nv_strcmp(p, "e"))
		len += snprintf(buf + len, sizeof(buf) - len, ",%s", "accept");
	else if (p != NULL && !nv_strcmp(p, "d"))
		len += snprintf(buf + len, sizeof(buf) - len, ",%s", "deny");
	else
		return 0;

	for (i = 0; i < num; i++) {
		snprintf(strKey, sizeof(strKey), "vfilter_client%d", i);
		p = nvram_safe_get_r(strKey, t, sizeof(t));
		if (p != NULL && !nv_strcmp(p, buf)) {
			found = i;
			break;
		}
	}

	if (found >= 0 && found < num) {
		snprintf(strSave, sizeof(strSave), "%d", num - 1);
		nvram_set("vfilter_client_max", strSave);
		for (i = found; i < (num - 1); i++) {
			snprintf(strKey, sizeof(strKey), "vfilter_client%d", i + 1);
			nvram_safe_get_r(strKey, strSave, sizeof(strSave));
			snprintf(strKey, sizeof(strKey), "vfilter_client%d", i);
			nvram_set(strKey, strSave);
		}
		snprintf(strKey, sizeof(strKey), "vfilter_client%d", num - 1);
		nvram_unset(strKey);
		return 1;
	}

	return 0;
#endif
	return 0;
}

int reset_acl_info(char *val, int idx, int subidx)
{
#if 0
	if (nv_strcmp(val, "1") == 0) {
		yexecl(NULL, "/usr/sbin/resetvfilter");
		sleep(1);
	}
	return 1;
#endif
	return 1;
}

int get_acl_info_count(void)
{
	return 0;
}

static char *yitoxa(char *dst, unsigned char *val, int valsize)
{
	const char *__xascii = "0123456789abcdef";
	char *p = dst;
	int c, i;

	for (i = 0; i < valsize; i++) {
		c = *val++;
		*p++ = __xascii[(c >> 4) & 0xf];
		*p++ = __xascii[c & 0xf];
	}
	*p = '\0';
	return dst;
}

static void dv_set_ssid_encryption(int idx, int subidx, int res)
{
	char prefix[12] = {0, };
	char param[32] = {0, }, tmp[32] = {0, };

	if (subidx == -1)
		snprintf(prefix, sizeof(prefix), "WLAN%d", idx);
	else
		snprintf(prefix, sizeof(prefix), "WLAN%d_VAP%d", idx, subidx);

	//APACRTL-336
	memset(param, 0, sizeof(param));
	snprintf(param, sizeof(param), "%s_WPA_AUTH", prefix);
	nvram_set(param, "0");

	if (2 <= res && res <= 9) { // WEP
		snprintf(param, sizeof(param), "%s_ENCRYPT", prefix);
		nvram_set(param, "1");
		snprintf(param, sizeof(param), "%s_WEP", prefix);
		if (res <= 5) { // WEP-64
			nvram_set(param, "1");
			snprintf(tmp, sizeof(tmp), "%d", res - 2);
		} else { // WEP-128
			nvram_set(param, "2");
			snprintf(tmp, sizeof(tmp), "%d", res - 6);
		}
		snprintf(param, sizeof(param), "%s_WEP_DEFAULT_KEY", prefix);
		nvram_set(param, tmp);

	} else if (res == 10 || res == 11 || res == 15 || res == 16) { // WPA
		snprintf(param, sizeof(param), "%s_ENCRYPT", prefix);
		nvram_set(param, "2");
		snprintf(param, sizeof(param), "%s_WPA_CIPHER_SUITE", prefix);
		if (res == 10 || res == 15) // TKIP
			nvram_set(param, "1");
		else // AES
			nvram_set(param, "2");
		//APACRTL-336
		memset(param, 0, sizeof(param));
		snprintf(param, sizeof(param), "%s_WPA_AUTH", prefix);
		if (res == 10 || res == 11)
			nvram_set(param, "2");  //PSK
		else if (res == 15 || res == 16)
			nvram_set(param, "1");  //EAP

	} else if (res == 12 || res == 13 || res == 17 || res == 18) { // WPA2
		snprintf(param, sizeof(param), "%s_ENCRYPT", prefix);
		nvram_set(param, "4");
		snprintf(param, sizeof(param), "%s_WPA2_CIPHER_SUITE", prefix);
		if (res == 12 || res == 17) // TKIP
			nvram_set(param, "1");
		else // AES
			nvram_set(param, "2");
		//APACRTL-336
		memset(param, 0, sizeof(param));
		snprintf(param, sizeof(param), "%s_WPA_AUTH", prefix);
		if (res == 12 || res == 13)
			nvram_set(param, "2");  //PSK
		else if (res == 17 || res == 18)
			nvram_set(param, "1");  //EAP

	} else if (res == 14) { // Dynamic WEP
		snprintf(param, sizeof(param), "%s_ENCRYPT", prefix);
		nvram_set(param, "1");
		snprintf(param, sizeof(param), "%s_WEP", prefix);
		nvram_set(param, "2");
		snprintf(param, sizeof(param), "%s_AUTH_TYPE", prefix);
		nvram_set(param, "2");
	} else { // OPEN
		snprintf(param, sizeof(param), "%s_ENCRYPT", prefix);
		nvram_set(param, "0");
	}

	snprintf(param, sizeof(param), "%s_x_LGAUTH", prefix);
	snprintf(tmp, sizeof(tmp), "%s_ENABLE_1X", prefix);
	if (res >= 14) { // RADIUS
		nvram_set(param, "4");
		nvram_set(tmp, "1");
	} else { // Personal
		nvram_set(param, "0");
		nvram_set(tmp, "0");
	}
}

static void dv_set_ssid_lgauth(int idx, int subidx, int res)
{
	char enable_1x[24] = {0, }, lgauth[24] = {0, };
	char val[4] = {0, };

	res -= 1;
	snprintf(val, sizeof(val), "%d", res);

	if (subidx == -1) {
		snprintf(enable_1x, sizeof(enable_1x), "WLAN%d_ENABLE_1X", idx);
		snprintf(lgauth, sizeof(lgauth), "x_WLAN%d_LGAUTH", idx);
	} else {
		snprintf(enable_1x, sizeof(enable_1x), "WLAN%d_VAP%d_ENABLE_1X", idx, subidx);
		snprintf(lgauth, sizeof(lgauth), "x_WLAN%d_VAP%d_LGAUTH", idx, subidx);
	}

	if (res == 0) { // 1x disable.
		nvram_set(enable_1x, "0");
		nvram_set(lgauth, "0");
	} else {
		nvram_set(enable_1x, "1");
		nvram_set(lgauth, val);
	}
}

static void dv_set_encrypt_mode(int idx, int subidx, int encryption, int lgauth)
{
	dv_set_ssid_encryption(idx, subidx, encryption);
	dv_set_ssid_lgauth(idx, subidx, lgauth);
}

//APACRTL-452
#define KEYLEN 64
int dv_set_wlan_key(int wl_idx, int wl_subidx, int mode, int auth, char *key)
{
	char nv_name[32] = {0, };
	char prefix[16] = {0, };
	char midfix[16] = {0, };
	int keyidx = 0;
	int keylen = 0;
	char buf[32] = {0, };

	if (wl_subidx == -1)
		snprintf(prefix, sizeof(prefix), "WLAN%d", wl_idx);
	else
		snprintf(prefix, sizeof(prefix), "WLAN%d_VAP%d", wl_idx, wl_subidx);

	if (auth == 1) {
		keylen = STRLEN(key);
		if (mode >= 2 && mode <= 9) { // WEP
			//key idx, bit
			if (mode >= 2 && mode <= 5) {
				keyidx = mode - 1;
				snprintf(midfix, sizeof(midfix), "WEP64");
			} else {
				keyidx = mode - 5;
				snprintf(midfix, sizeof(midfix), "WEP128");
			}

			if (((keylen == 10 || keylen == 26) && ishex(key)) || (keylen == 5 || keylen == 13)) {
				//ascii or hex
				snprintf(nv_name, sizeof(nv_name), "%s_WEP_KEY_TYPE", prefix);
				//if ascii -> key conversion
				if (keylen == 5 || keylen == 13) { // ascii
					yitoxa(buf, (unsigned char *)key, keylen);
					nvram_set(nv_name, "0");

					snprintf(nv_name, sizeof(nv_name), "%s_%s_KEY%d", prefix, midfix, keyidx);
					nvram_set(nv_name, buf);
					snprintf(nv_name, sizeof(nv_name), "%s_%s_KEY_TYPE%d", prefix, midfix, keyidx);
					nvram_set(nv_name, "0");
				} else {
					nvram_set(nv_name, "1");
					snprintf(nv_name, sizeof(nv_name), "%s_%s_KEY%d", prefix, midfix, keyidx);
					nvram_set(nv_name, key);
					snprintf(nv_name, sizeof(nv_name), "%s_%s_KEY_TYPE%d", prefix, midfix, keyidx);
					nvram_set(nv_name, "1");
				}
			}
		} else if (mode >= 10 && mode <= 13) { // WPA or WPA2
			if (8 <= keylen && keylen <= 63) {
				snprintf(nv_name, sizeof(nv_name), "%s_WPA_PSK", prefix);
				nvram_set(nv_name, key);
			}
		}
	}

	return 0;
}

//APACRTL-452
int set_encrypt_mode(void)
{
	int i;
	int ret = 0, chg = 0, set_cnt = 0;
	char prefix[12] = {0, };
	char filename1[64] = {0, };
	char filename2[64] = {0, };

	int wl_idx = 0;
	int wl_subidx = 0;

	int keylen = 0;
	int keyidx = 0;

	int mode[MAX_WL_INTF * MAX_WL_BSS];
	int auth[MAX_WL_INTF * MAX_WL_BSS];
	char key[MAX_WL_INTF * MAX_WL_BSS][KEYLEN];

	char midfix[16] = {0, };
	char nv_name[32] = {0, };

	for (i = 0; i < MAX_WL_INTF * MAX_WL_BSS; i++) {
		get_wlan_idxes(i + 1, &wl_idx, &wl_subidx);
		chg = 0;

		mode[i] = 0;
		auth[i] = 0;

		//encryption mode, 1x auth type
		memset(filename1, 0, sizeof(filename1));
		memset(filename2, 0, sizeof(filename2));
		if (wl_subidx == -1) {
			snprintf(filename1, sizeof(filename1), "/tmp/cwmp/.wlan%d_encryption", wl_idx);
			snprintf(filename2, sizeof(filename2), "/tmp/cwmp/.wlan%d_1x_auth", wl_idx);
		} else {
			snprintf(filename1, sizeof(filename1), "/tmp/cwmp/.wlan%d_vap%d_encryption", wl_idx, wl_subidx);
			snprintf(filename2, sizeof(filename2), "/tmp/cwmp/.wlan%d_vap%d_1x_auth", wl_idx, wl_subidx);
		}

		if (yfcat(filename1, "%d", &mode[i]) > 0) {
			set_cnt++;
			chg++;
			unlink(filename1);
		}

		if (yfcat(filename2, "%d", &auth[i]) > 0) {
			set_cnt++;
			chg++;
			unlink(filename2);
		}

		//key
		memset(&key[i][0], 0, KEYLEN);
		memset(filename1, 0, sizeof(filename1));
		if (wl_subidx == -1) {
			snprintf(prefix, sizeof(prefix), "WLAN%d", wl_idx);
			snprintf(filename1, sizeof(filename1), "/tmp/cwmp/.wlan%d_encryption_key", wl_idx);
		} else {
			snprintf(prefix, sizeof(prefix), "WLAN%d_VAP%d", wl_idx, wl_subidx);
			snprintf(filename1, sizeof(filename1), "/tmp/cwmp/.wlan%d_vap%d_encryption_key", wl_idx, wl_subidx);
		}

		if (access(filename1, F_OK) == 0) {
			yfcat(filename1, "%s", &key[i][0]);
			set_cnt++;
			chg++;
			unlink(filename1);

			if (STRLEN(&key[i][0]) < 5 || STRLEN(&key[i][0]) >= KEYLEN) {
				ret -= chg;
				continue;
			}
		}

		//Value vaild check
		if (mode[i] < 1 && mode[i] > 18) {
			ret -= chg;
			continue;
		}
		if (auth[i] < 1 && auth[i] > 7) {
			ret -= chg;
			continue;
		}

		//For Non-set(Mode, Auth)
		if (mode[i] == 0)
			mode[i] = get_ssid_encryption(wl_idx, wl_subidx);

		if (auth[i] == 0)
			auth[i] = get_ssid_lgauth(wl_idx, wl_subidx);

		//Value conflict Check
		if (mode[i] <= 9 && auth[i] >= 5) {
			ret -= chg;
			continue;
		} else if ((mode[i] >= 10 && mode[i] <= 13) && auth[i] >= 2) {
			ret -= chg;
			continue;
		} else if (mode[i] >= 14 && auth[i] != 5) {
			ret -= chg;
			continue;
		}
		//For Non-set(Key)
		if (STRLEN(&key[i][0]) == 0 && auth[i] == 1) {
			if (mode[i] >= 2 && mode[i] <= 9) { // WEP
				if (mode[i] >= 2 && mode[i] <= 5)
					keyidx = mode[i] - 1;
				else
					keyidx = mode[i] - 5;

				snprintf(nv_name, sizeof(nv_name), "%s_%s_KEY%d", prefix, midfix, keyidx);
				get_ssid_encryptionkey_wep(&key[i][0], KEYLEN, wl_idx, wl_subidx, mode[i], keyidx);

			} else if (mode[i] >= 10 && mode[i] <= 13) { // WPA or WPA2
				snprintf(nv_name, sizeof(nv_name), "%s_WPA_PSK", prefix);
				nvram_safe_get_r(nv_name, &key[i][0], KEYLEN);
			}
		}

		//Key Check
		keylen = STRLEN(&key[i][0]);
		if (keylen) {
			if (auth[i] == 1) {
				if (mode[i] >= 2 && mode[i] <= 5) { //WEP64
					if ((keylen == 10 && !ishex(&key[i][0])) || (keylen != 5 && keylen != 10)) {
						ret -= chg;
						continue;
					}
				} else if (mode[i] >= 6 && mode[i] <= 9) { //WEP128
					if ((keylen == 26 && !ishex(&key[i][0])) || (keylen != 13 && keylen != 26)) {
						ret -= chg;
						continue;
					}
				} else if (mode[i] >= 10 && mode[i] <= 13) { // WPA or WPA2
					if (keylen < 8 || keylen > 63) {
						ret -= chg;
						continue;
					}
				}
			} else {
				ret -= chg;
				continue;
			}
		}
	}

	//Conflict Case
	if (ret != 0)
		return -set_cnt;

	//Success Case
	for (i = 0; i < MAX_WL_INTF * MAX_WL_BSS; i++) {
		get_wlan_idxes(i + 1, &wl_idx, &wl_subidx);
		dv_set_encrypt_mode(wl_idx, wl_subidx, mode[i], auth[i]);
		dv_set_wlan_key(wl_idx, wl_subidx, mode[i], auth[i], &key[i][0]);
	}

	return ret;
}

//Auto / Manual, channel, bandwitdh, sideband
int set_wlchannel(void) //APACRTL-349, 404
{
	char buf[16] = {0, };
	char filename[64] = {0, };
	char band[8] = {0, };
	int i, set_cnt = 0;
	//2.4G
	int wl1_auto_ch = -1, wl1_ch = -1, wl1_width = -1, wl1_side = -1;
	//5G
	int wl0_auto_ch = -1, wl0_ch = -1, wl0_width = -1;
	int zone = 0;		//abcd
	int valid = -1;		//Is it vaild?
	bss_info wl1_bss, wl0_bss;
	int wl1_bw, wl1_sb, wl0_bw, wl0_sb;

	//wl1_auto_ch
	snprintf(filename, sizeof(filename), "%s", "/tmp/cwmp/.wlan1_auto");
	if (yfcat(filename, "%d", &wl1_auto_ch) > 0)
		set_cnt++;
	unlink(filename);

	//wl1_ch
	snprintf(filename, sizeof(filename), "%s", "/tmp/cwmp/.wlan1_ch");
	if (yfcat(filename, "%d", &wl1_ch) > 0)
		set_cnt++;
	unlink(filename);

	//wl1_width
	snprintf(filename, sizeof(filename), "%s", "/tmp/cwmp/.wlan1_width");
	if (yfcat(filename, "%d", &wl1_width) > 0)
		set_cnt++;
	unlink(filename);

	//wl0_auto_ch
	snprintf(filename, sizeof(filename), "%s", "/tmp/cwmp/.wlan0_auto");
	if (yfcat(filename, "%d", &wl0_auto_ch) > 0)
		set_cnt++;
	unlink(filename);

	//wl0_ch
	snprintf(filename, sizeof(filename), "%s", "/tmp/cwmp/.wlan0_ch");
	if (yfcat(filename, "%d", &wl0_ch) > 0)
		set_cnt++;
	unlink(filename);

	//wl0_width
	snprintf(filename, sizeof(filename), "%s", "/tmp/cwmp/.wlan0_width");
	if (yfcat(filename, "%d", &wl0_width) > 0)
		set_cnt++;
	unlink(filename);

	//wl0_band
	snprintf(filename, sizeof(filename), "%s", "/tmp/cwmp/.wlan0_band");
	if (yfcat(filename, "%s", band) > 0)
		set_cnt++;
	else
		nvram_safe_get_r("WLAN0_zone", band, sizeof(band));
	unlink(filename);
	if (STRLEN(band) <= 0 || STRLEN(band) > 4)
		return -set_cnt;

	memset(&wl1_bss, 0, sizeof(bss_info));
	if (getWlBssInfo("wlan1", &wl1_bss, &wl1_bw, &wl1_sb) < 0) {
		fprintf(stderr, "Get bssinfo failed!\n");
		return -set_cnt;
	}

	memset(&wl0_bss, 0, sizeof(bss_info));
	if (getWlBssInfo("wlan0", &wl0_bss, &wl0_bw, &wl0_sb) < 0) {
		fprintf(stderr, "Get bssinfo failed!\n");
		return -set_cnt;
	}

	//2.4GHz Channel Set
	if (wl1_auto_ch == 0)
		wl1_ch = 0;
	else if (wl1_auto_ch > 0 && wl1_ch == -1)
		wl1_ch = wl1_auto_ch;
	else if (wl1_auto_ch == -1) {
		if (nvram_atoi("WLAN1_CHANNEL", 0) == 0)	//if (wl1_bss.channel == 0)
			wl1_ch = 0;
		else if (wl1_ch == -1)
			wl1_ch = wl1_bss.channel;
	}

	//2.4GHz Width, Sideband Set
	if (wl1_width != -1) {
		if (wl1_width == BAND_20MHZ) {
			wl1_width = 0;
		} else {
			if (wl1_width == 1) {	//40HMz Lower
				wl1_side = 1;
			} else {				//40MHz Upper
				wl1_width = 1;
				wl1_side = 0;
			}
		}
	} else {
		if (wl1_bw == 20) {
			wl1_width = 0;
		} else {
			wl1_width = 1;

			if (wl1_sb == 'A')	//40HMz Lower
				wl1_side = 1;
			else					//40MHz Upper
				wl1_side = 0;
		}
	}

	if (wl1_width == -1 || (wl1_width == 1 && wl1_side == -1))
		return -set_cnt;

	//2.4GHz Set
	if (wl1_ch != 0) {
		if (wl1_width == 0 || (wl1_width == 1 && ((wl1_side == 1 && wl1_ch <= 9) || (wl1_side == 0 && wl1_ch >= 5)))) {  //1. 20MHz거나 or 2. 40MHz이면서 사이드밴드에 따른 채널이 유효하면
			snprintf(buf, sizeof(buf), "%d", wl1_ch);
			nvram_set("WLAN1_CHANNEL", buf);

			snprintf(buf, sizeof(buf), "%d", wl1_width);
			nvram_set("WLAN1_CHANNEL_BONDING", buf);

			if (wl1_width == 1 && wl1_side != -1) {
				snprintf(buf, sizeof(buf), "%d", wl1_side);
				nvram_set("WLAN1_CONTROL_SIDEBAND", buf);
			}
		} else {
			return -set_cnt;
		}
	} else {
		nvram_set("WLAN1_CHANNEL", "0");

		snprintf(buf, sizeof(buf), "%d", wl1_width);
		nvram_set("WLAN1_CHANNEL_BONDING", buf);

		if (wl1_width == 1 && wl1_side != -1) {
			snprintf(buf, sizeof(buf), "%d", wl1_side);
			nvram_set("WLAN1_CONTROL_SIDEBAND", buf);
		}
	}

	//5GHz Channel Set
	if (wl0_auto_ch == 0)
		wl0_ch = 0;
	else if (wl0_auto_ch > 0 && wl0_ch == -1)
		wl0_ch = wl0_auto_ch;
	else if (wl0_auto_ch == -1) {
		if (nvram_atoi("WLAN0_CHANNEL", 0) == 0)	//if (wl0_bss.channel == 0)
			wl0_ch = 0;
		else if (wl0_ch == -1)
			wl0_ch = wl0_bss.channel;
	}

	//5GHz Width, Sideband Set
	if (wl0_width != -1) {
		if (wl0_width == BAND_20MHZ)		//20MHz
			wl0_width = 0;
		else if (wl0_width == BAND_40MHZ)	//40MHz
			wl0_width = 1;
		else								//80MHz
			wl0_width = 2;
	} else {
		if (wl0_bw == 20)
			wl0_width = 0;
		else if (wl0_bw == 40)
			wl0_width = 1;
		else
			wl0_width = 2;
	}

	for (i = 0; i < STRLEN(band); i++) {
		switch (band[i]) {
		case 'a':
			zone |= 0x08;
			break;
		case 'b':
			zone |= 0x04;
			break;
		case 'c':
			zone |= 0x02;
			break;
		case 'd':
			zone |= 0x01;
			break;
		default:
			return -set_cnt;
		}
	}

	if (wl0_width == -1 || zone == 0)
		return -set_cnt;

	memset(band, 0, sizeof(band));
	if (zone & 0x08)
		band[STRLEN(band)] = 'a';
	if (zone & 0x04)
		band[STRLEN(band)] = 'b';
	if (zone & 0x02)
		band[STRLEN(band)] = 'c';
	if (zone & 0x01)
		band[STRLEN(band)] = 'd';

	//5GHz Set
	if (wl0_ch != 0) {

		valid = valid_chan(wl0_ch, zone, wl0_width);

		if (valid) {
			snprintf(buf, sizeof(buf), "%d", wl0_ch);
			nvram_set("WLAN0_CHANNEL", buf);

			snprintf(buf, sizeof(buf), "%d", wl0_width);
			nvram_set("WLAN0_CHANNEL_BONDING", buf);

			if (wl0_width == 1) {
				if (valid == 1) {
					nvram_set("WLAN0_CONTROL_SIDEBAND", "1");	//Lower
				} else {
					nvram_set("WLAN0_CONTROL_SIDEBAND", "0");	//Upper
				}
			}
			nvram_set("WLAN0_zone", band);
		} else {
			return -set_cnt;
		}
	} else {
		nvram_set("WLAN0_CHANNEL", "0");

		snprintf(buf, sizeof(buf), "%d", wl0_width);
		nvram_set("WLAN0_CHANNEL_BONDING", buf);

		nvram_set("WLAN0_zone", band);
	}

	return 0;
}

char *get_wbr_ifname(void)
{
	if (nvram_match_r("REPEATER_ENABLED1", "1"))
		return "wlan0-vxd";
	else if (nvram_match_r("REPEATER_ENABLED2", "1"))
		return "wlan1-vxd";
	else
		return NULL;
}

unsigned int get_interference(int wl_idx)
{
	return 2;
}

int set_interference(int wl_idx, int res)
{
	return 0;
}

void start_wps(void)
{
	unlink("/tmp/wscd_status");
	yexecl(NULL, "/usr/sbin/wps_pbc /var/wps/registrar");
}

void stop_wps(void)
{
	killall(SIGTERM, "wscd");
	unlink("/tmp/wscd_status");
}

//APACRTL-395
int is_conn_iot_dongle()
{
	char conn_stat[8] = {0, };
	char dev_name[16] = {0, };
	char dev_filename[32] = {0, };
	char dev_id[8] = {0, };

	if (yfcat("/tmp/usb/acm_status", "%s %s", conn_stat, dev_name) == 2) {
		if (strstr(conn_stat, "add") != NULL) {
			snprintf(dev_filename, sizeof(dev_filename), "/tmp/usb/%s", dev_name);
			if (yfcat(dev_filename, "%s", dev_id) == 1) {
				if (nv_strcmp(dev_id, "0658") == 0)
					return 1;
			}
		}
	}

	return 0;
}

char *get_acs_domain(char *val, int bufsz, int idx, int subidx)
{
	if (!val)
		return NULL;

	nvram_safe_get_r("dv_acs_server", val, MIN(bufsz, 80));
	return val;
}

char *get_acs_ip(char *val, int bufsz, int idx, int subidx)
{
	if (!val)
		return NULL;

	snprintf(val, bufsz, "%s", "00");
	return val;
}

char *get_ids_domain(char *val, int bufsz, int idx, int subidx)
{
	if (!val)
		return NULL;

	nvram_safe_get_r("dv_ids_server", val, MIN(bufsz, 80));
	return val;
}

char *get_ids_ip(char *val, int bufsz, int idx, int subidx)
{
	snprintf(val, bufsz, "%s", "00");
	return val;
}

char *get_static_route(char *buf, int bufsz, int idx, int subidx)
{
	char *val = NULL, *p = NULL;
	char tmpBuf[64] = {0, }, chBuf[64] = {0, };
	char key[32] = {0, };
	int  count, i;
	char *onoff;
	char *dstip, *netmask, *gateway;
	int len;
	char t[64] = {0, };

	buf[0] = 0;
	count = MIN(atoi(nvram_safe_get_r("statical_route_max", t, sizeof(t))), 10);
	if (bufsz == 0 || count == 0) {
		strncpy(buf, "00", 2);
		buf[2] = '\0';
		return buf;
	}

	len = 0;
	for (i = 0; i < count; i++) {
		snprintf(key, sizeof(key), "statical_route%d", i);
		val = nvram_safe_get_r(key, tmpBuf, sizeof(tmpBuf));
		if (!val || val[0] == 0)
			continue;
		p = tmpBuf;
		onoff = strsep(&p, ":");
		if (!onoff)
			continue;
		dstip = strsep(&p, ":");
		if (!dstip)
			continue;
		netmask = strsep(&p, ":");
		if (!netmask)
			continue;
		gateway = strsep(&p, ":");
		if (!gateway)
			continue;
		if (!STRNCASECMP(onoff, "off"))
			snprintf(chBuf, sizeof(chBuf), "0,%s,%s,%s", dstip, netmask, gateway);
		else if (!STRNCASECMP(onoff, "on"))
			snprintf(chBuf, sizeof(chBuf), "1,%s,%s,%s", dstip, netmask, gateway);
		else
			continue;

		if (len + STRLEN(chBuf) >= bufsz)
			break;
		if (len > 0)
			len += snprintf(buf + len, bufsz, "%s", "|");
		len += snprintf(buf + len, bufsz - len, "%s", chBuf);
	}

	val[len] = '\0';
	return val;
}

unsigned int get_ssid_loop_cnt(int idx, int subidx, int isTx)
{
	int ret;
	char tmp[16] = {0, };
	char str[32] = {0, };
	char *arg[2];
	char buf[128] = {0, };
	FILE *fp = NULL;

	get_wlan_ifname_from_idx(tmp, sizeof(tmp), idx, subidx);

	snprintf(str, sizeof(str), "/proc/%s/stats", tmp);
	fp = fopen(str, "r");
	if (fp == NULL)
		return 0;

	memset(tmp, 0, sizeof(tmp));
	memset(str, 0, sizeof(str));

	if (isTx)
		snprintf(tmp, sizeof(tmp), "%s", "tx");
	else
		snprintf(tmp, sizeof(tmp), "%s", "rx");
	snprintf(str, sizeof(str), "%s_only_data_bytes_high", tmp);

	while (fgets(buf, sizeof(buf), fp) != NULL) {

		if (strstr(buf, str)) {
			ret = ystrargs(buf, arg, 2, ":", 0);

			if (ret != 2) {
				fclose(fp);

				return 0;
			}
			fclose(fp);

			return strtoul(arg[1], NULL, 10);
		}
	}
	fclose(fp);

	return 0;
}

int nvram_atoi(char *name, int dfl)
{
	char *p = nvram_get(name);

	return (p) ? (int)strtol(p, NULL, 0) : dfl;
}

unsigned int get_uptime_mo()
{
	struct sysinfo info;
	unsigned int uptime = 0;

	sysinfo(&info);
	uptime = (unsigned int)info.uptime;

	return uptime;
}

char *get_gateway_mac(char *buf, int bufsz)
{
	char gw_ip[32] = {0, };
	char str[256] = {0, };
	char arp_ip[32] = {0, };
	char arp_mac[32] = {0, };
	FILE *fp = NULL;
	int ret = 0;

	if (!buf || bufsz == 0)
		return NULL;

	if (get_gateway(gw_ip, sizeof(gw_ip)) == NULL)
		return NULL;

	yexecl(NULL, "cp /proc/net/arp /tmp/.arp_cache");

	fp = fopen("/tmp/.arp_cache", "r");
	if (!fp)
		return NULL;

	while (fgets(str, sizeof(str), fp) != NULL) {
		if (strstr(str, "IP address") != NULL)
			continue;

		//IP address   HW type   Flags   HW address   Mask   Device
		ret = sscanf(str, "%31s %*s %*s %31s %*s %*s", arp_ip, arp_mac);
		if (ret != 2) {
			buf[0] = '\0';
			break;
		}

		if (nv_strcmp(arp_ip, gw_ip) == 0) {
			snprintf(buf, bufsz, "%s", conv_mac_format(arp_mac));
			break;
		}
	}

	fclose(fp);
	unlink("/tmp/.arp_cache");
	return buf;
}

#define BRDIO_FILE  "/proc/brdio"
static int get_port_status(int type, int port)
{
	int fd;
	struct phreq phr;

	if (port < PH_MINPORT || port > PH_MAXPORT)
		return 0;

	fd = open(BRDIO_FILE, O_RDWR);
	if (fd < 0)
		return 0;

	memset(&phr, 0, sizeof(phr));
	phr.phr_port = port;
	if (ioctl(fd, PHGIO, &phr)) {
		perror("PHGIO");
		close(fd);
		return 0;
	}

	close(fd);

	switch (type) {
	case TYPE_LINK:
		if (!(phr.phr_optmask & PHF_PWRDOWN)) { 	//Not pwr down
			if (!(phr.phr_optmask & PHF_LINKUP))
				return NOLINK;
			else
				return LINKUP;
		} else
			return DISABLE;
		break;

	case TYPE_MAXBT:
		if (phr.phr_optmask & PHF_LINKUP) {	//LINKUP
			if (phr.phr_optmask & PHF_10M)
				return M_10;
			else if (phr.phr_optmask & PHF_100M)
				return M_100;
			else if (phr.phr_optmask & PHF_500M)
				return M_500;
			else if (phr.phr_optmask & PHF_1000M)
				return M_1000;
		} else {
			if (!(phr.phr_optmask & (PHF_ENFORCE_NO_AUTONEG | PHF_ENFORCE_POLL))) {
				return M_AUTO;
			} else {
				if (phr.phr_optmask & PHF_10M)
					return M_10;
				else if (phr.phr_optmask & PHF_100M)
					return M_100;
				else if (phr.phr_optmask & PHF_500M)
					return M_500;
				else if (phr.phr_optmask & PHF_1000M)
					return M_1000;
			}
		}
		break;

	case TYPE_DUPLEX:
		if (phr.phr_optmask & PHF_LINKUP) {	//LINKUP
			return phr.phr_optmask & PHF_FDX ? D_FULL : D_HALF;
		} else {
			if (!(phr.phr_optmask & (PHF_ENFORCE_NO_AUTONEG | PHF_ENFORCE_POLL))) {
				return D_AUTO;
			} else {
				return phr.phr_optmask & PHF_FDX ? D_FULL : D_HALF;
			}
		}
		break;

	default:
		break;
	}

	//Unsupported Type
	return 0;
}

//Connection Status
static char *get_port_link_status(int pn)
{
	int status = 0;
	status = get_port_status(TYPE_LINK, pn);
	switch (status) {
	case LINKUP:
		return "Up";
		break;

	case NOLINK:
		return "NoLink";
		break;

	case DISABLE:
		return "Disable";
		break;

	default:
		//Not Supported Status
		return "NotSupported";
		break;
	}
}

char *get_lan_link_conn_status(int idx)
{
	int pn = 0;
	pn = get_lan_port_num_from_idx(idx);
	return get_port_link_status(pn);
}

char *get_wan_link_conn_status()
{
	return get_port_link_status(WAN_PORT);
}

//MaxBitrate
static char *get_port_maxbitrate(int pn)
{
	int bitrate = 0;
	bitrate = get_port_status(TYPE_MAXBT, pn);
	switch (bitrate) {
	case M_10:
		return "10";

	case M_100:
		return "100";

	case M_500:
		return "500";

	case M_1000:
		return "1000";

	case M_AUTO:
		return "Auto";

	default:
		//Not Supported Status
		return "NotSupported";
	}
}

char *get_lan_maxbitrate(int idx)
{
	int pn = 0;
	pn = get_lan_port_num_from_idx(idx);
	return get_port_maxbitrate(pn);
}

char *get_wan_maxbitrate()
{
	return get_port_maxbitrate(WAN_PORT);
}

//DuplexMode
static char *get_port_duplex(int pn)
{
	int mode = 0;
	mode = get_port_status(TYPE_DUPLEX, pn);
	switch (mode) {
	case D_HALF:
		return "Half";

	case D_FULL:
		return "Full";

	case D_AUTO:
		return "Auto";

	default:
		//Not Supported Status
		return "NotSupported";
	}
}

char *get_lan_duplex(int idx)
{
	int pn = 0;
	pn = get_lan_port_num_from_idx(idx);
	return get_port_duplex(pn);
}

char *get_wan_duplex()
{
	return get_port_duplex(WAN_PORT);
}

int get_twamp_status(char *buf, int bufsz)
{
	FILE *fp = NULL;

	if (!buf || bufsz < 1)
		return 0;

	yexecl(">/tmp/.twamp_result", "TWAMP-STATUS");

	fp = fopen("/tmp/.twamp_result", "r");
	if (fp) {
		fgets(buf, bufsz, fp);
		syslog(LOG_INFO, DVLOG_MARK_ADMIN "TWAMP Status %s", buf);
		fclose(fp);
	}

	return 1;
}

unsigned int get_twamp_listen_port(void)
{
	unsigned int port = 40862;
	char buf[512] = "";
	char *ptr;

	nvram_safe_get_r("twamp_sender", buf, sizeof(buf));

	ptr = strchr(buf, '|');

	if (ptr)
		port = (unsigned int)atoi(ptr + 1);

	return port;
}

static void parse_twamp_sender_acl_list(char *buf, size_t bufsz)
{
	char tmp[1024] = "";
	char *ptr = NULL, *bar_ptr = NULL, *tmp_ptr = &tmp[0];
	size_t buf_idx = 0;

	nvram_safe_get_r("twamp_sender", tmp, sizeof(tmp));

	while ((ptr = strsep(&tmp_ptr, ",\n")) != NULL) {
		bar_ptr = strchr(ptr, '|');

		if (bar_ptr) {
			if (bufsz - buf_idx < 16)
				break;

			*bar_ptr = '\0';
			buf_idx += snprintf(buf + buf_idx, bufsz - buf_idx, "%s;", ptr);
		}
	}

	if (buf_idx > 0)
		buf[buf_idx - 1] = '\0';	//remove ";"
}

int get_twamp_sender_acl(char *buf, int bufsz)
{
	FILE *fp = NULL;

	if (!buf || bufsz < 1)
		return 0;

	yexecl(">/tmp/.twamp_result", "TWAMP-STATUS");

	fp = fopen("/tmp/.twamp_result", "r");
	if (fp) {
		fgets(buf, bufsz, fp);	//first line : STATUS
		memset(buf, 0, bufsz);
		fgets(buf, bufsz, fp);	//second line : ACL LIST
		if (STRLEN(buf) < 1)
			parse_twamp_sender_acl_list(buf, bufsz);

		fclose(fp);
	}

	return 1;
}

unsigned int get_wan_pause_frame_status(void)
{
	return get_port_pause_frame_status(WAN_PORT);
}

int set_wan_pause_frame_status(unsigned int val)
{
	return set_port_pause_frame_status(WAN_PORT, val);
}

unsigned int get_port_pause_frame_status(int port)
{
	char key[32] = "";
	char val[32] = "";
	char *ptr = NULL;
	char *setting = NULL;

	int rx_en = 0;
	int tx_en = 0;

	if (port < LAN_PORT1 || port > WAN_PORT)
		return 0;

	snprintf(key, sizeof(key), "x_port_%d_config", port);
	nvram_safe_get_r(key, val, sizeof(val));

	setting = &val[0];

	//example : down_auto_-rxpause_-txpause
	while ((ptr = strsep(&setting, "_\t\n")) != NULL) {
		if (strstr(ptr, "rxpause")) {
			if (ptr[0] != '-')
				rx_en = 1;
		} else if (strstr(ptr, "txpause")) {
			if (ptr[0] != '-')
				tx_en = 2;
		}
	}

	return rx_en + tx_en;
}

int set_port_pause_frame_status(int port, unsigned int val)
{
	int res = 0;
	char *args[4];
	char key[32] = "";
	char old_val[64] = "", str_val[64] = "";
	char pause_val[32] = "";

	if (port < LAN_PORT1 || port > WAN_PORT)
		return 0;

	snprintf(key, sizeof(key), "x_port_%d_config", port);
	nvram_safe_get_r(key, old_val, sizeof(old_val));
	//example : down_auto_-rxpause_-txpause
	res = ystrargs(old_val, args, _countof(args), "_\t\r\n", 0);
	if (res != 4)
		return 0;

	switch (val) {
	case 1:	//RX enable
		snprintf(pause_val, sizeof(pause_val), "rxpause_-txpause");
		break;

	case 2:	//TX enable
		snprintf(pause_val, sizeof(pause_val), "-rxpause_txpause");
		break;

	case 3:	//RX + TX enable
		snprintf(pause_val, sizeof(pause_val), "rxpause_txpause");
		break;

	case 0:	//All disable
	default:
		snprintf(pause_val, sizeof(pause_val), "-rxpause_-txpause");
		break;
	}				/* -----  end switch  ----- */

	snprintf(str_val, sizeof(str_val), "%s_%s_%s", args[0], args[1], pause_val);
	nvram_set(key, str_val);

	return 1;
}
