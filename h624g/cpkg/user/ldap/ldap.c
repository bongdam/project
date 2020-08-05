#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/syslog.h>

#include <libytool.h>
#include <bcmnvram.h>
#include <furl.h>
#include <shutils.h>
#include "ldap.h"

#ifdef __CONFIG_GNT2100__
#define VENDOR	"DEONET"
#else
#define VENDOR	"HFR"
#endif

#define NORMAL_COLOR           "\033[0m"
#define GREEN_COLOR            "\033[1;32m"

#define LDAP_DEF_URL "apldap.skbroadband.com:22380"

#define MAX_TRY     4
#define MAX_TIMEO   4000

#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif

#if 1
#define MIBLIST "WLAN0_WLAN_DISABLED "\
                "WLAN0_VAP0_WLAN_DISABLED "\
                "WLAN0_VAP1_WLAN_DISABLED "\
                "WLAN0_VAP2_WLAN_DISABLED "\
                "WLAN0_VAP3_WLAN_DISABLED "\
                "WLAN0_HIDDEN_SSID "\
                "WLAN0_VAP0_HIDDEN_SSID "\
                "WLAN0_VAP1_HIDDEN_SSID "\
                "WLAN0_VAP2_HIDDEN_SSID "\
                "WLAN0_VAP3_HIDDEN_SSID "\
                "WLAN0_RS_IP "\
                "WLAN0_RS_PORT "\
                "WLAN0_RS_PASSWORD "\
                "WLAN0_VAP0_RS_IP "\
                "WLAN0_VAP0_RS_PORT "\
                "WLAN0_VAP0_RS_PASSWORD "\
                "WLAN0_VAP1_RS_IP "\
                "WLAN0_VAP1_RS_PORT "\
                "WLAN0_VAP1_RS_PASSWORD "\
                "WLAN0_VAP2_RS_IP "\
                "WLAN0_VAP2_RS_PORT "\
                "WLAN0_VAP2_RS_PASSWORD "\
                "WLAN0_ACCOUNT_RS_IP "\
                "WLAN0_ACCOUNT_RS_PORT "\
                "WLAN0_ACCOUNT_RS_PASSWORD "\
                "WLAN0_VAP0_ACCOUNT_RS_IP "\
                "WLAN0_VAP0_ACCOUNT_RS_PORT "\
                "WLAN0_VAP0_ACCOUNT_RS_PASSWORD "\
                "WLAN0_VAP1_ACCOUNT_RS_IP "\
                "WLAN0_VAP1_ACCOUNT_RS_PORT "\
                "WLAN0_VAP1_ACCOUNT_RS_PASSWORD "\
                "WLAN0_VAP2_ACCOUNT_RS_IP "\
                "WLAN0_VAP2_ACCOUNT_RS_PORT "\
                "WLAN0_VAP2_ACCOUNT_RS_PASSWORD "\
				"WLAN1_WLAN_DISABLED "\
                "WLAN1_VAP0_WLAN_DISABLED "\
                "WLAN1_VAP1_WLAN_DISABLED "\
                "WLAN1_VAP2_WLAN_DISABLED "\
                "WLAN1_VAP3_WLAN_DISABLED "\
                "WLAN1_HIDDEN_SSID "\
                "WLAN1_VAP0_HIDDEN_SSID "\
                "WLAN1_VAP1_HIDDEN_SSID "\
                "WLAN1_VAP2_HIDDEN_SSID "\
                "WLAN1_VAP3_HIDDEN_SSID "\
                "WLAN1_RS_IP "\
                "WLAN1_RS_PORT "\
                "WLAN1_RS_PASSWORD "\
                "WLAN1_VAP0_RS_IP "\
                "WLAN1_VAP0_RS_PORT "\
                "WLAN1_VAP0_RS_PASSWORD "\
                "WLAN1_VAP1_RS_IP "\
                "WLAN1_VAP1_RS_PORT "\
                "WLAN1_VAP1_RS_PASSWORD "\
                "WLAN1_VAP2_RS_IP "\
                "WLAN1_VAP2_RS_PORT "\
                "WLAN1_VAP2_RS_PASSWORD "\
                "WLAN1_ACCOUNT_RS_IP "\
                "WLAN1_ACCOUNT_RS_PORT "\
                "WLAN1_ACCOUNT_RS_PASSWORD "\
                "WLAN1_VAP0_ACCOUNT_RS_IP "\
                "WLAN1_VAP0_ACCOUNT_RS_PORT "\
                "WLAN1_VAP0_ACCOUNT_RS_PASSWORD "\
                "WLAN1_VAP1_ACCOUNT_RS_IP "\
                "WLAN1_VAP1_ACCOUNT_RS_PORT "\
                "WLAN1_VAP1_ACCOUNT_RS_PASSWORD "\
                "WLAN1_VAP2_ACCOUNT_RS_IP "\
                "WLAN1_VAP2_ACCOUNT_RS_PORT "\
                "WLAN1_VAP2_ACCOUNT_RS_PASSWORD "\
                "OP_MODE "\
                "DNS_MODE "\
                "DNS1 "\
                "DNS2 "\
                "DHCP_CLIENT_START "\
                "DHCP_CLIENT_END "\
                "SCRLOG_ENABLED "\
                "REMOTELOG_ENABLED "\
                "REMOTELOG_SERVER "\
                "IGMP_DISABLED "\
                "IGMP_PROXY_DISABLED "\
                "IP_ADDR "\
                "SUBNET_MASK"
#else
#define MIBLIST "WLAN_DISABLED "\
                "WLAN0_VAP0_WLAN_DISABLED "\
                "WLAN0_VAP1_WLAN_DISABLED "\
                "WLAN0_VAP2_WLAN_DISABLED "\
                "WLAN0_VAP3_WLAN_DISABLED "\
                "WLAN0_HIDDEN_SSID "\
                "WLAN0_VAP0_HIDDEN_SSID "\
                "WLAN0_VAP1_HIDDEN_SSID "\
                "WLAN0_VAP2_HIDDEN_SSID "\
                "WLAN0_VAP3_HIDDEN_SSID "\
                "WLAN0_RS_IP "\
                "WLAN0_RS_PORT "\
                "WLAN0_RS_PASSWORD "\
                "WLAN0_VAP0_RS_IP "\
                "WLAN0_VAP0_RS_PORT "\
                "WLAN0_VAP0_RS_PASSWORD "\
                "WLAN0_VAP1_RS_IP "\
                "WLAN0_VAP1_RS_PORT "\
                "WLAN0_VAP1_RS_PASSWORD "\
                "WLAN0_VAP2_RS_IP "\
                "WLAN0_VAP2_RS_PORT "\
                "WLAN0_VAP2_RS_PASSWORD "\
                "WLAN0_ACCOUNT_RS_IP "\
                "WLAN0_ACCOUNT_RS_PORT "\
                "WLAN0_ACCOUNT_RS_PASSWORD "\
                "WLAN0_VAP0_ACCOUNT_RS_IP "\
                "WLAN0_VAP0_ACCOUNT_RS_PORT "\
                "WLAN0_VAP0_ACCOUNT_RS_PASSWORD "\
                "WLAN0_VAP1_ACCOUNT_RS_IP "\
                "WLAN0_VAP1_ACCOUNT_RS_PORT "\
                "WLAN0_VAP1_ACCOUNT_RS_PASSWORD "\
                "WLAN0_VAP2_ACCOUNT_RS_IP "\
                "WLAN0_VAP2_ACCOUNT_RS_PORT "\
                "WLAN0_VAP2_ACCOUNT_RS_PASSWORD "\
                "OP_MODE "\
                "DNS_MODE "\
                "DNS1 "\
                "DNS2 "\
                "DHCP_CLIENT_START "\
                "DHCP_CLIENT_END "\
                "SCRLOG_ENABLED "\
                "REMOTELOG_ENABLED "\
                "REMOTELOG_SERVER "\
                "IGMP_PROXY_DISABLED "\
                "IP_ADDR "\
                "SUBNET_MASK"
#endif

static void init_ldap_cfg(void);
static void setup_fwinfo(int id, const char *value);
static int ldap_cfg_handle(struct variable_s *pldap, const char *down_cfg_val);
static void ldapcfg_save_to_file(FILE *fp, char *name, char *value);
static int apply_ldapcfg_system(void);
static char *get_id_name_ldapcfg_map(int id);
static int ldap_debug_enabled;

void dv_dbg_printf(char *fmt, ...);
#define LDAP_PRINT( ... ) do{if(ldap_debug_enabled) dv_dbg_printf( __VA_ARGS__ );} while(0)

void dv_dbg_printf(char *fmt, ...)
{
	int ret;
	va_list ap;

	printf("" GREEN_COLOR "LDAP" NORMAL_COLOR ": ");
	va_start(ap, fmt);
	ret += vprintf(fmt, ap);
	va_end(ap);
}

const CFG_ID_NAME ldap_cfgmap[] = {
	STR(FORMAT_VERSION),
	STR(model),
	STR(cfg_filename),
	STR(dv_autoup_auth_svr),
	STR(dv_ldap_autoup_domain),
	STR(FW_VER),
	STR(dv_ldap_autoup_file),
	STR(syslog_server_url),
	STR(DNS_MODE),
	STR(OP_MODE),
	STR(DHCP_CLIENT_START),
	STR(DHCP_CLIENT_END),
	STR(x_SNMP_ENABLE),
	STR(x_SNMP_GET_COMMUNITY),
	STR(x_SNMP_SET_COMMUNITY),
	STR(x_SNMP_TRAP_COMMUNITY),
	STR(x_WIFI_TRAP_SERVER),
	STR(x_holepunch_enabled),
	STR(PORT_NEGO),
	STR(PORT_SPEED),
	STR(PORT_DUPLEX),
	STR(PORT_ENABLE),
	STR(PORT_RATE_LIMIT),
	STR(IGMP_DISABLED),
	STR(IGMP_PROXY_DISABLED),
	STR(IGMP_FAST_LEAVE_DISABLED),
	STR(x_igmp_expire_time),
	STR(x_igmp_query_interval),
	STR(x_igmp_query_res_interval),
	STR(dv_ldap_autoup_enabled),
	STR(AUTO_UPGRADE_SVR),
	STR(FIRMWARE_FILE),
	STR(WLAN_DISABLED),
	STR(SSID_ENABLE),
	STR(HIDDEN_SSID),
	STR(DESIGNATED_RATE_LIMIT_SSID),
	STR(RADIUS_AUTH_SSID),
	STR(MAC_AUTH_SSID),
	STR(RADIUS_SVR_INFO),
	STR(ACCOUNT_SVR_INFO),
#if defined(__WIFI_DUAL__)
	//STR(WIFI_5G_ENABLE),
	STR(WIFI_5G_DISABLED),
	STR(SSID_5G_ENABLE),
	STR(HIDDEN_5G_SSID),
	STR(DESIGNATED_5G_RATE_LIMIT_SSID),
	STR(RADIUS_AUTH_5G_SSID),
	STR(MAC_AUTH_5G_SSID),
	STR(RADIUS_SVR_5G_INFO),
	STR(ACCOUNT_SVR_5G_INFO),
#endif
	STR(HP_SVR_IP_PORT),
	STR(x_holepunch_control_interval),
	STR(x_auto_reboot_on_idle),
	STR(x_auto_uptime),
	STR(x_auto_wan_port_idle),
	STR(x_auto_hour_range),
	{-1, "unknown"}
};

static variable vartbl[] = {
	{FORMAT_VERSION, "format_version", ldap_cfg_handle, NULL, T_STRING | FLG_DVNV},
	{cfg_filename, "cfg_filename", ldap_cfg_handle, NULL, T_STRING | FLG_DVNV},
	{model, "model", ldap_cfg_handle, NULL, T_STRING},
	{dv_autoup_auth_svr, "auth_svr", ldap_cfg_handle, NULL, T_STRING | FLG_DVNV},
	{dv_ldap_autoup_domain, "fw_svr", ldap_cfg_handle, NULL, T_STRING},
	{FW_VER, "fw_ver", ldap_cfg_handle, NULL, T_STRING},
	{dv_ldap_autoup_file, "fw_file", ldap_cfg_handle, NULL, T_STRING},
	{syslog_server_url, "syslog_svr", ldap_cfg_handle, NULL, T_STRING | FLG_DVNV | FLG_REBOOT},
	{DNS_MODE, "auto_dns", ldap_cfg_handle, NULL, FLG_APMIB | T_ONOFF | FLG_TOGGLE | FLG_REBOOT},
	{OP_MODE, "nat_enable", ldap_cfg_handle, NULL, FLG_APMIB | T_ONOFF | FLG_TOGGLE | FLG_REBOOT},
	{DHCP_CLIENT_START, "nat_startip", ldap_cfg_handle, NULL, T_STRING | FLG_APMIB | FLG_REBOOT},
	{DHCP_CLIENT_END, "nat_endip", ldap_cfg_handle, NULL, T_STRING | FLG_APMIB | FLG_REBOOT},
	{x_SNMP_ENABLE, "snmp_enable", ldap_cfg_handle, NULL, FLG_DVNV | T_ONOFF | FLG_REBOOT},
	{x_SNMP_GET_COMMUNITY, "snmp_get_community", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING | FLG_REBOOT},
	{x_SNMP_SET_COMMUNITY, "snmp_set_community", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING | FLG_REBOOT},
	{x_SNMP_TRAP_COMMUNITY, "snmp_trap_community", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING | FLG_REBOOT},
	{x_WIFI_TRAP_SERVER, "wifi_traffic_trap_svr", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING | FLG_REBOOT},
	{x_holepunch_enabled, "hp_enable", ldap_cfg_handle, NULL, FLG_DVNV | T_ONOFF | FLG_REBOOT},
	{PORT_NEGO, "port_nego", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING},
	{PORT_SPEED, "port_speed", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING},
	{PORT_DUPLEX, "port_duplex", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING},
	{PORT_ENABLE, "port_enable", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING},
	{PORT_RATE_LIMIT, "port_rate_limit", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING},
	{IGMP_DISABLED, "igmp_enable", ldap_cfg_handle, NULL, FLG_APMIB | T_ONOFF | FLG_TOGGLE | FLG_REBOOT},
	{IGMP_PROXY_DISABLED, "igmp_proxy_enable", ldap_cfg_handle, NULL, FLG_APMIB | T_ONOFF | FLG_TOGGLE | FLG_REBOOT},
	{IGMP_FAST_LEAVE_DISABLED, "igmp_fast_leave_enable", ldap_cfg_handle, NULL,
	 FLG_DVNV | T_ONOFF | FLG_TOGGLE | FLG_REBOOT},
	{x_igmp_expire_time, "member_expire_time", ldap_cfg_handle, NULL, FLG_DVNV | T_INT | FLG_REBOOT},
	{x_igmp_query_interval, "query_interval", ldap_cfg_handle, NULL, FLG_DVNV | T_INT | FLG_REBOOT},
	{x_igmp_query_res_interval, "query_response_interval", ldap_cfg_handle, NULL, FLG_DVNV | T_INT | FLG_REBOOT},
	{dv_ldap_autoup_enabled, "auto_upgrade_enable", ldap_cfg_handle, NULL, T_ONOFF},
	//{ AUTO_UPGRADE_SVR,             "auto_upgrade_svr",             ldap_cfg_handle,    NULL,   T_STRING},
	//{ FIRMWARE_FILE,                "firmware_file",                ldap_cfg_handle,    NULL,   T_STRING },
	{WLAN_DISABLED, "wifi_2.4g_enable", ldap_cfg_handle, NULL, FLG_APMIB | T_ONOFF | FLG_TOGGLE | FLG_REBOOT},
	{SSID_ENABLE, "ssid_enable", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT},
	{HIDDEN_SSID, "hidden_ssid", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT},
	{DESIGNATED_RATE_LIMIT_SSID, "designated_rate_limit_ssid", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING | FLG_REBOOT},
	{RADIUS_AUTH_SSID, "radius_auth_ssid", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT},
	{MAC_AUTH_SSID, "mac_auth_ssid", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT},
	{RADIUS_SVR_INFO, "radius_svr_info", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT},
	{ACCOUNT_SVR_INFO, "account_svr_info", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT},
#if defined(__WIFI_DUAL__)
	//{ WIFI_5G_ENABLE,                "wifi_5g_enable",              ldap_cfg_handle,    NULL,   FLG_APMIB| T_ONOFF |FLG_TOGGLE | FLG_REBOOT | FLG_5G},
	{WIFI_5G_DISABLED, "wifi_5g_enable", ldap_cfg_handle, NULL, FLG_APMIB | T_ONOFF | FLG_TOGGLE | FLG_REBOOT | FLG_5G},
	{SSID_5G_ENABLE, "ssid_enable", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT | FLG_5G},
	{HIDDEN_5G_SSID, "hidden_ssid", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT | FLG_5G},
	{DESIGNATED_5G_RATE_LIMIT_SSID, "designated_rate_limit_ssid", ldap_cfg_handle, NULL,
	 FLG_DVNV | T_STRING | FLG_REBOOT | FLG_5G},
	{RADIUS_AUTH_5G_SSID, "radius_auth_ssid", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT | FLG_5G},
	{MAC_AUTH_5G_SSID, "mac_auth_ssid", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT | FLG_5G},
	{RADIUS_SVR_5G_INFO, "radius_svr_info", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT | FLG_5G},
	{ACCOUNT_SVR_5G_INFO, "account_svr_info", ldap_cfg_handle, NULL, FLG_APMIB | T_STRING | FLG_REBOOT | FLG_5G},
#endif
	{HP_SVR_IP_PORT, "hp_svr_ip_port", ldap_cfg_handle, NULL, T_STRING | FLG_DVNV},
	{x_holepunch_control_interval, "hp_interval", ldap_cfg_handle, NULL, FLG_DVNV | T_STRING | FLG_REBOOT},
	{x_auto_reboot_on_idle, "auto_reboot_on_idle", ldap_cfg_handle, NULL, T_ONOFF},
	{x_auto_uptime, "uptime", ldap_cfg_handle, NULL, T_STRING},
	{x_auto_wan_port_idle, "wan_port_idle", ldap_cfg_handle, NULL, T_ONOFF},
	{x_auto_hour_range, "hour_range", ldap_cfg_handle, NULL, T_STRING},
	{-1, NULL, NULL, NULL, 0},
};

#define LAN_PORT_MAX    4
#define WLAN_AUTH_MAX   5

#define WLAN_RADIO		2

static struct ldap_cfg_t ldap_cfg;
static struct fwinfo fw_info;
static int tries;
static char flsbuffer[3072];
static struct in_addr ippool[2];
static struct wlan_ep_auth_info_t wlan_auth[WLAN_RADIO][WLAN_AUTH_MAX];
static struct lan_port_t lan[LAN_PORT_MAX];

static int is_dgt(char c, int hex)
{
	if ((c >= '0') && (c <= '9'))
		return 1;
	if (hex) {
		c = toupper(c);
		if ((c >= 'A') && (c <= 'F'))
			return 1;
	}
	return 0;
}

static int is_digits(char *s, int len, int hex)
{
	int i;

	for (i = 0; i < len; i++) {
		if (!is_dgt(s[i], hex)) {
			return 0;
		}
	}
	return 1;
}

static char *read_line(char *p, char *out, int maxlen)
{
	int c;
	char *e;

	if (p == NULL)
		return NULL;

	/* skip leading white spaces */
	while (*p && isspace(*p))
		p++;

	if (*p == '\0')
		return NULL;

	for (e = (out + maxlen - 1); (c = *p) && (out < e); p++) {
		switch (c) {
		case '\n':
			*out = 0;
			return ++p;
		case '\r':
			if (p[1] == '\n') {
				*out = 0;
				return &p[2];
			}
			// fall thru
		default:
			*out++ = c;
			break;
		}
	}
	*out = 0;
	return p;
}

static int strtoi(const char *s, int *ret)
{
	char *q;

	if (!s || !s[0])
		return -1;

	errno = 0;
	*ret = strtol(s, &q, 0);
	if (errno)
		return -1;

	if (s == q || !q || (*q && !isspace(*q))) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

void sys_reboot(void)
{
	reboot(RB_AUTOBOOT);
}

static int safe_atoi(const char *s, int ndefault)
{
	int n;

	if (strtoi(s, &n))
		n = ndefault;
	return n;

}

static int build_url(char *url, const char *dir, const char *fname)
{
	char buf[128];

	if (!dir || !dir[0] || !fname || !fname[0])
		return -1;

	url[0] = '\0';
	if (!strncasecmp(dir, "http", 4))
		strcpy(buf, &dir[4]);
	else
		strcpy(buf, dir);

	if (buf[0] != 0)
		ystrtrim(buf, ":/ \t\r\n");
	if (buf[0]) {
		sprintf(url, "http://%s/", buf);
		strcpy(buf, fname);
		ystrtrim(buf, ":/ \t\r\n");
		strcat(url, buf);
		return 0;
	}
	return -1;
}

static int fls_mibget(const char *name, char *buf, int len)
{
	char line[128];
	char *p = flsbuffer;
	char *eq;

	if (!name || name[0] == 0)
		return -1;

	buf[0] = '\0';
	while ((p = read_line(p, line, sizeof(line)))) {
		eq = strchr(line, '=');
		if (eq) {
			*eq++ = '\0';
			if (line[0] != 0)
				ydespaces(line);
			if (eq[0] != 0)
				ystrtrim(eq, " \t\r\n\"");
			if (!strcmp(name, line)) {
				snprintf(buf, len, eq);
				return 0;
			}
		}
	}
	LDAP_PRINT("fls_mibget: %s not found\n", name);
	return -1;
}

static int validate_type(const char *val, int type)
{
	int res;
	struct in_addr ip;

	if (!val)
		return 0;

	switch (type & T_MASK) {
	case T_STRING:
		return 0;
	case T_INT:
		return strtoi(val, &res);
	case T_IPV4:
		if (inet_aton(val, &ip) != 0)
			return 0;
		break;
	case T_PORT:
		if (!strtoi(val, &res) && res > 0 && res <= 0x10000)
			return 0;
		break;
	case T_ONOFF:
		return 0;
		break;
	default:
		break;
	}
	return -1;
}

static int flash_mib_mget(char *buffer, int len)
{
	char value[128];
	char *plist = strdup(MIBLIST);
	char *p, *q;
	int n;

	for (p = plist; (q = strsep(&p, " \t\r\n"));) {
		ydespaces(q);
		if (q[0] == '\0')
			continue;
		//flash_get_mib(value, sizeof(value), (!strncasecmp(q, "WLAN", 4)) ? "wlan0" : NULL, q);
		nvram_get_r_def(q, value, sizeof(value), (!strncasecmp(q, "WLAN0", 4)) ? "wlan0" : "wlan1");
		n = snprintf(buffer, len, "%s=%s\n", q, value);
		if (n >= len)
			break;
		len -= n;
		buffer += n;
	}
	free(plist);
	*buffer = '\0';
}

static int invalid_cfg_format(char *cfg_value)
{
	char tmp[80];
	char *f_date, *f_version;
	char *dv_date, *dv_version;
	int cfg_date = 0, cfg_ver = 0;
	int dvnv_date = 0, dvnv_ver = 0;

	if ((dv_version = nvram_get("FORMAT_VERSION"))) {
		sprintf(&tmp[0], "%s", dv_version);
		dv_version = &tmp[0];
		dv_date = strsep(&dv_version, ":");
		if (dv_date && dv_version) {
			dvnv_date = strtoul(&dv_date[0], NULL, 10);
			dvnv_ver = strtoul(&dv_version[0], NULL, 10);

			sprintf(tmp, "%s", cfg_value);
			f_version = &tmp[0];
			f_date = strsep(&f_version, ":");
			if (f_date && f_version) {
				cfg_date = strtoul(f_date, NULL, 10);
				cfg_ver = strtoul(f_version, NULL, 10);
				if (dvnv_date > cfg_date ||
				    ((dvnv_date == cfg_date) && cfg_ver < dvnv_ver)) {
					LDAP_PRINT("invalid format version(%s:%s)\n", f_date, f_version);
					ldap_cfg.normal_down_cfg = 0;
					return 1;
				}
			}
		}
	}
	return 0;
}

static int parse_config(struct fwinfo *info, char *fmem, int *flgs)
{
	char buf[128];
	variable *v;
	char *value, *name;
	struct in_addr ip;
	int restart = 0;
	int check_format_ver = 0;
	int section_5g = 0;
	int flag = 0;

	info->binpath[0] = '\0';
	info->binname[0] = '\0';
	info->new.all = 0;
	memset(ippool, 0, sizeof(ippool));
	flash_mib_mget(flsbuffer, sizeof(flsbuffer));

	check_format_ver = safe_atoi(nvram_get("check_format_version"), 1);
	while ((fmem = read_line(fmem, buf, sizeof(buf)))) {
		value = buf;
		name = strsep(&value, "=");
		if (!name)
			continue;

		ystrtrim(name, " \t\r\n\"");

		/* Comment */
		if (name[0] == '#')
			continue;

		if (!strcasecmp(name, "model")) {
			if (value[0] == 0 || strcasecmp(value, SYS_NAME)) {
				ldap_cfg.normal_down_cfg = 0;
				LDAP_PRINT("(cfg)model=\"%s\" is invalid, so ignore cfg file\n", value);
				break;
			}
		}

		if (!strcasecmp(name, "[end]"))
			ldap_cfg.normal_down_cfg = 1;

		if (check_format_ver && !strcasecmp(name, "format_version")) {
			if (invalid_cfg_format(value)) {
				break;
			}
		}

		if (section_5g && (!strcasecmp(name, "[wlan_2.4g]") || strstr(name, "_2.4g]"))) {
			section_5g = 0;
		} else if (!section_5g && (!strcasecmp(name, "[wifi_5g]") || strstr(name, "_5g]"))) {
			section_5g = 1;
		}

		if (value)
			ystrtrim(value, " \t\r\n\"");
		else
			value = "";

		for (v = &vartbl[0]; v->name; v++) {
			if (!strcasecmp(v->name, name)) {
				flag = v->val_type & 0x7f8;
				/* do a set of sanity check */
				if ((flag & FLG_NILNOK) && !value[0])
					break;

				if ((flag & FLG_INANY) && !value[0])
					value = "0.0.0.0";

				if (validate_type(value, flag))
					break;

				if ((flag & FLG_INETATON)) {
					inet_aton(value, &ip);
					if (ip.s_addr == 0 || ip.s_addr == (in_addr_t)-1)
						break;
				}

				if (section_5g) {
//#if !defined(__WIFI_DUAL__)
					if (v->id >= WLAN_DISABLED && v->id <= ACCOUNT_SVR_INFO) {
						continue;
					}
//#endif
				}

				LDAP_PRINT("%s=%s\n", name, value);
				if (v->setvar) {
					v->setvar(v, value);
				}
				break;
			}
		}
	}
	if (ldap_cfg.normal_down_cfg) {
		restart = apply_ldapcfg_system();

		if (flgs) {
			*flgs = restart;
			/*if (restart)
			   syslog(LOG_INFO, "<D>change cfg, system reboot in ldap"); */
		}
	}
	LDAP_PRINT("normal_down_cfg %d, upgrade_keep_going %d \n", ldap_cfg.normal_down_cfg, info->upgrade_keep_going);
	return ! !(ldap_cfg.normal_down_cfg & info->upgrade_keep_going);
}

static int initenv(struct fwinfo *info)
{
	char dir[128], tmp[128], serial[128];
	char wlan_mac[30], version[30], str_ver[32];;
	int mj, mi, cf;
	char f_tmp[128];
	FILE *f;

	memset(info, 0, sizeof(*info));
	f_tmp[0] = 0;
	yfcat("/etc/version", "%*s %s", str_ver);
	if (sscanf(str_ver, "%d.%d.%d", &mj, &mi, &cf) == 3) {
		info->cur.i.major = mj;
		info->cur.i.minor = mi;
		info->cur.i.conf = cf;
		sprintf(version, "%d.%d.%d", mj, mi, cf);

	}
	nvram_get_r_def("x_autoup_auth_svr", dir, sizeof(dir), LDAP_DEF_URL);
	/* For legacy 800 devices */
	if (!strcmp(dir, "apldap.skbroadband.com") && strlen(dir) == strlen("apldap.skbroadband.com"))
		strcpy(dir, "apldap.skbroadband.com:22380");

	/* For empty serial number */
	nvram_safe_get_r("HW_SERIAL_NO", serial, sizeof(serial));
	
	nvram_get_r_def("HW_NIC1_ADDR", tmp, sizeof(tmp), NULL);
	
	nvram_get_r_def("HW_WLAN_ADDR", wlan_mac, sizeof(wlan_mac), NULL);
	ydespaces(tmp);
	ydespaces(wlan_mac);
	ydespaces(version);
	sprintf(info->confurl, "http://%s/config?proto=2&wan=%s&wifi=%s&version=%s&vendor=" VENDOR,
		dir, tmp, wlan_mac, version);

	info->background = safe_atoi(nvram_get("x_autoup_forever"), 0);

	return (info->confurl[0] && info->cur.all) ? 0 : -1;
}

static long uptime_us(void)
{
	FILE *fp;
	unsigned int a, b;

	if ((fp = fopen("/proc/uptime", "r"))) {
		fscanf(fp, "%u.%u", &a, &b);
		fclose(fp);

		return ((a * 1000000) + (b * 10 * 1000));
	}
	return -1;
}

static int dv_sleep(int secs, long usecs)
{
	struct timeval tv;
	int n;

	tv.tv_sec = secs;
	tv.tv_usec = usecs;

	while (1) {
		if ((n = select(0, NULL, NULL, NULL, &tv)) < 0) {
			if (errno != EINTR)
				continue;
		}
		return n;
	}
}

#define RETRY_INTERVAL(x) (x == 0)? 10000000: (x==1)? 30000000: (x==2)? 60000000: 0
static int do_wget(struct fwstat *fbuf, int *exp, int timeo_ms, const char *url)
{
	char cmd[256];
	int try;
	long ts, waiths;
	long n;

	snprintf(cmd, sizeof(cmd) - 13, "wget -q -O - \"%s\"%s",
		 url, (fw_info.quiet) ? " 2>/dev/null" : "");

	LDAP_PRINT("%s\n", cmd);
	for (try = 0; try < MAX_TRY; try++) {
		ts = uptime_us();
		waiths = RETRY_INTERVAL(try);
		++*exp;
		if (!furl(cmd, timeo_ms, (p_read_f) fw_read_callback, (void *)fbuf))
			return (!fbuf->lasterror && fbuf->rcvlen > 0) ? 0 : -1;
		waiths -= ((n = uptime_us()) - ts);
		if (waiths < 0)
			waiths = 0;
		dv_sleep(0, waiths);
	}
	return -1;
}

static inline int newer_version(version_t *new, version_t *cur)
{
	return ((new->all == cur->all) ||
		(new->i.major < cur->i.major) ||
		((new->i.major == cur->i.major) && (new->i.minor < cur->i.minor)) ||
		((new->i.major == cur->i.major) && (new->i.minor == cur->i.minor) && (new->i.conf < cur->i.conf))) ? 0 : 1;
}

static void sig_term(int signo)
{
	_exit(-1);
}

static void init_ldap_cfg(void)
{
	int i;

	memset(&ldap_cfg, 0, sizeof(ldap_cfg));
	for (i = 0; i < WLAN_AUTH_MAX; i++) {
		memset(&wlan_auth[i], 0, sizeof(struct wlan_ep_auth_info_t));
		if (i < LAN_PORT_MAX) {
			memset(&lan[i], 0, sizeof(struct lan_port_t));
		}
	}
	memset(ippool, 0, sizeof(ippool));
}

#define YES_NO(x) ( x =='y' || x == 'Y' || x == '1') ? 1: 0
#define IS_NO(x) ( x =='n' || x == 'N' || x == '0') ? 1: 2
static void setup_fwinfo(int id, const char *value)
{
	int mj, mi, cf;
	char prefix[80];
	char buf[128];
	char *p;
	int enable, prefix_use;

	if (!value || value[0] == 0)
		return;

	switch (id) {
	case dv_ldap_autoup_domain:
		//case AUTO_UPGRADE_SVR: /*remove item*/
		fw_info.binpath[0] = 0;
		if ((p = nvram_get("x_ldap_autoup_domain"))) {
			snprintf(&fw_info.binpath[0], sizeof(fw_info.binpath), "%s", p);
			LDAP_PRINT("force use upgrade server url[%s] in webpage", fw_info.binpath);
		} else if (value[0] != 0) {
			snprintf(&fw_info.binpath[0], sizeof(fw_info.binpath), "%s", value);
		}
		break;
	case FW_VER:
		if (sscanf(value, "%d.%d.%d", &mj, &mi, &cf) == 3) {
			fw_info.new.i.major = mj;
			fw_info.new.i.minor = mi;
			fw_info.new.i.conf = cf;
		}
		break;
	case dv_ldap_autoup_file:
		//case FIRMWARE_FILE: /*not used*/
		prefix_use = safe_atoi(nvram_get("x_autoup_prefix_use"), 1);
		nvram_get_r_def("x_ldap_autoup_prefix", prefix, sizeof(prefix), "firmware?name=");
		ydespaces(prefix);

		if ((p = nvram_get("x_ldap_autoup_file"))) {
			snprintf(&fw_info.binname[0], sizeof(fw_info.binname), "%s%s", (prefix_use) ? prefix : "", p);
			LDAP_PRINT("force use firmware name[%s] in webpage", fw_info.binname);
		} else if (value[0] != 0) {
			snprintf(&fw_info.binname[0], sizeof(fw_info.binname), "%s%s", (prefix_use) ? prefix : "", value);
		}
		break;
	case dv_ldap_autoup_enabled:
		/* 0: force off 2: force on 1: ldap cfg */
		enable = safe_atoi(nvram_get("x_ldap_autoup_enabled"), 1);
		if (enable == 1) {
			fw_info.upgrade_keep_going = YES_NO(value[0]);
		} else {
			LDAP_PRINT("force use upgrade mode in webpage, active:%s\n", (enable) ? "turn on" : "turn off");
			fw_info.upgrade_keep_going = enable;
		}
		break;
	default:
		break;
	}
}

static int ldap_cfg_handle(struct variable_s *pldap, const char *down_cfg_val)
{
	int id = pldap->id;
	int flag = pldap->val_type;
	int index;
	int value = -1;
	char down_cfg[128];

	if (id > MAX_ID)
		return -1;

	if (!down_cfg_val || down_cfg_val[0] == 0) {
		if ((id != SSID_ENABLE) && (id != HIDDEN_SSID) &&
		    (id != SSID_5G_ENABLE) && (id != HIDDEN_5G_SSID))
			return -1;
	}

	down_cfg[0] = 0;
	sprintf(&down_cfg[0], "%s", (down_cfg_val[0] == 0) ? "" : down_cfg_val);

	index = ldap_cfg.entry;
	ldap_cfg.item[index].id = id;
	ldap_cfg.item[index].flag = flag;

	if (flag & T_ONOFF) {
		if (!strcasecmp(down_cfg, "y") ||
		    !strcasecmp(down_cfg, "Y") ||
		    down_cfg[0] == '1')
			value = 1;
		else if (!strcasecmp(down_cfg, "n") ||
		         !strcasecmp(down_cfg, "N") ||
			 down_cfg[0] == '0')
			value = 0;
		else
			return -1;

		if (flag & FLG_TOGGLE)
			value = !value;

		sprintf(&down_cfg[0], "%d", value);
	}
	snprintf(ldap_cfg.item[index].value, sizeof(ldap_cfg.item[index].value) - 1, "%s", down_cfg);

	//if ( (id >= dv_ldap_autoup_domain && id <= dv_ldap_autoup_file) || (id >= dv_ldap_autoup_enabled && id <= FIRMWARE_FILE) )
	if ((id >= dv_ldap_autoup_domain && id <= dv_ldap_autoup_file) || (id == dv_ldap_autoup_enabled))
		setup_fwinfo(id, down_cfg);

	return (ldap_cfg.entry++);
}

static void ldapcfg_save_to_file(FILE *fp, char *name, char *value)
{
	fprintf(fp, "%s=%s\n", name, value);
}

static char *get_id_name_ldapcfg_map(int id)
{
	int i = 0;

	while (ldap_cfgmap[i].id != -1) {
		if (id == ldap_cfgmap[i].id)
			return ldap_cfgmap[i].name;
		i++;
	}
	return NULL;
}

static int apply_ldapcfg_nvram(char *name, char *ldap_value, int flag)
{
	char *nv_val;
	int restart = 0;

	if (!name || name[0] == 0 || !ldap_value)
		return 0;

	//nv_val = dvnv_get_def(name, "");
	nv_val = nvram_safe_get(name);
	if (nv_val && nv_val[0] != 0)
		ystrtrim(nv_val, " \t\r\n\"");

	if (!nv_val || nv_val[0] == 0 || strcmp(nv_val, ldap_value)) {
		if (flag & FLG_REBOOT) {
			LDAP_PRINT("Diff nvram(%s:%s)|cfg(%s:%s)- set restart.\n", name, (nv_val) ? nv_val : "", name, ldap_value);
			restart = 1;
		}
		nvram_set(name, ldap_value);

	   if (strcmp(name, "WLAN1_WLAN_DISABLED") == 0) {
		   nvram_set ("WLAN0_VAP3_WLAN_DISABLED", ldap_value);
		}
		//nvram_commit();
	}
	return restart;
}

static int apply_ldapcfg_apmib(const char *name, char *ldap_value, int flag)
{
	char buf[80];
	int restart = 0;

	if (!name || name[0] == 0 || !ldap_value)
		return 0;

	fls_mibget(name, buf, sizeof(buf));

	if (buf[0] != 0 && strcmp(buf, ldap_value)) {
		if (flag & FLG_REBOOT) {
			LDAP_PRINT("Diff apmib(%s:%s)|cfg(%s:%s)- set restart.\n", name, buf, name, ldap_value);
			restart = 1;
		}
		if (!strcmp(name, "OP_MODE")) {
			if (atoi(ldap_value) == 1) {
				nvram_set("DHCP", "0");
			} else {
				nvram_set("DHCP", "2");
			}
		}
		nvram_set(name, ldap_value);
		//nvram_commit();
	}
	return restart;
}

#define WLAN_SSID_ACTIVE(x) (x == 1)? "0": "1"
#define WLAN_DELIM  "|,:\r\n\t"
#define WLAN_IS_RATELIMIT(x) (x > 0 && x <= 100)? 1: 0

static char wlan_ssid_snmp[2][5][80];

void translate_control_code(char *buffer)
{
	int i = 0;
	char tmpBuf[200], *p1 = buffer;

	while (*p1) {
		if (*p1 != '\\')
			tmpBuf[i++] = *p1;
		p1++;
	}
	tmpBuf[i] = '\0';
	sprintf(&buffer[0], &tmpBuf[0]);
}

static void int_wlan_ssid_name(void)
{
	char tmp[80];
	char wlan_name[80];
	int i, j;

	for (j = 0; j < 2; j++) {
		for (i = 0; i < 4; i++) {
			if (i == 0)
				sprintf(wlan_name, "WLAN%d_SSID", j);
			else
				sprintf(wlan_name, "WLAN%d_VAP%d_SSID", j, i - 1);

			//flash_get_mib(tmp, sizeof(tmp), NULL, wlan_name);
			nvram_get_r_def(wlan_name, tmp, sizeof(tmp), NULL);
			if (tmp[0] != 0) {
				translate_control_code(tmp);
				sprintf(wlan_ssid_snmp[j][i], "%s", tmp);
			}

			LDAP_PRINT("SSID INFO[%d][%d]=%s\n", j, i, wlan_ssid_snmp[j][i]);
		}
	}
}

static int notify_value_index(char *v)
{
	char *p, *sp;
	int count = 0;

	if (!v || v[0] == 0)
		return -1;

	p = strtok_r(v, ",", &sp);
	while ((p = strchr(&p[count], '|')))
		count++;

	return (count + 2);
}

static int apply_wlan_setup(char *name, struct ldap_item *ldap_p)
{
	int i, j;
	char *saveptr;
	int id = ldap_p->id;
	int flag = ldap_p->flag;
	int set_flag = 0;
	char tmp[128], tmp1[128];
	int wlan_idx = -1;
	int wlan_radio = -1;
	char *p;
	int restart = 0;
	const char *mib_name;
	char *mib_value;
	char nvram_name_tx[80], nvram_name_rx[80];
	char rate_limit[10];
	struct wlan_ratelimit_t wlan_rate[2][4];
	int ratelimit;
	struct in_addr ip;
	char buf[80];
	int idx = 0;
	int match = 0;
	int value_index = 0;
	int iw = 0;
	int rv = 1;
	struct wlan_ssid_t wlan_enable[2][5] = {
		{{"WLAN0_WLAN_DISABLED", 0},
		 {"WLAN0_VAP0_WLAN_DISABLED", 0},
		 {"WLAN0_VAP1_WLAN_DISABLED", 0},
		 {"WLAN0_VAP2_WLAN_DISABLED", 0},
		 {NULL, -1}},
		{{"WLAN1_WLAN_DISABLED", 0},
		 {"WLAN1_VAP0_WLAN_DISABLED", 0},
		 {"WLAN1_VAP1_WLAN_DISABLED", 0},
		 {"WLAN1_VAP2_WLAN_DISABLED", 0},
		 {NULL, -1}}
	};
	struct wlan_ssid_t wlan_hidden[2][5] = {
		{{"WLAN0_HIDDEN_SSID", 0},
		 {"WLAN0_VAP0_HIDDEN_SSID", 0},
		 {"WLAN0_VAP1_HIDDEN_SSID", 0},
		 {"WLAN0_VAP2_HIDDEN_SSID", 0},
		 {NULL, -1}},
		{{"WLAN1_HIDDEN_SSID", 0},
		 {"WLAN1_VAP0_HIDDEN_SSID", 0},
		 {"WLAN1_VAP1_HIDDEN_SSID", 0},
		 {"WLAN1_VAP2_HIDDEN_SSID", 0},
		 {NULL, -1}}
	};
	struct wlan_auth_t wlan_radius_name[2][5] = {
		{{"WLAN0_RS_IP", "WLAN0_RS_PORT", "WLAN0_RS_PASSWORD"},
		 {"WLAN0_VAP0_RS_IP", "WLAN0_VAP0_RS_PORT", "WLAN0_VAP0_RS_PASSWORD"},
		 {"WLAN0_VAP1_RS_IP", "WLAN0_VAP1_RS_PORT", "WLAN0_VAP1_RS_PASSWORD"},
		 {"WLAN0_VAP2_RS_IP", "WLAN0_VAP2_RS_PORT", "WLAN0_VAP2_RS_PASSWORD"},
		 {(char *)0, (char *)0, (char *)0}},
		{{"WLAN1_RS_IP", "WLAN1_RS_PORT", "WLAN1_RS_PASSWORD"},
		 {"WLAN1_VAP0_RS_IP", "WLAN1_VAP0_RS_PORT", "WLAN1_VAP0_RS_PASSWORD"},
		 {"WLAN1_VAP1_RS_IP", "WLAN1_VAP1_RS_PORT", "WLAN1_VAP1_RS_PASSWORD"},
		 {"WLAN1_VAP2_RS_IP", "WLAN1_VAP2_RS_PORT", "WLAN1_VAP2_RS_PASSWORD"},
		 {(char *)0, (char *)0, (char *)0}}
	};
	struct wlan_auth_t wlan_account_name[2][5] = {
		{{"WLAN0_ACCOUNT_RS_IP", "WLAN0_ACCOUNT_RS_PORT", "WLAN0_ACCOUNT_RS_PASSWORD"},
		 {"WLAN0_VAP0_ACCOUNT_RS_IP", "WLAN0_VAP0_ACCOUNT_RS_PORT", "WLAN0_VAP0_ACCOUNT_RS_PASSWORD"},
		 {"WLAN0_VAP1_ACCOUNT_RS_IP", "WLAN0_VAP1_ACCOUNT_RS_PORT", "WLAN0_VAP1_ACCOUNT_RS_PASSWORD"},
		 {"WLAN0_VAP2_ACCOUNT_RS_IP", "WLAN0_VAP2_ACCOUNT_RS_PORT", "WLAN0_VAP2_ACCOUNT_RS_PASSWORD"},
		 {(char *)0, (char *)0, (char *)0}},
		{{"WLAN1_ACCOUNT_RS_IP", "WLAN1_ACCOUNT_RS_PORT", "WLAN1_ACCOUNT_RS_PASSWORD"},
		 {"WLAN1_VAP0_ACCOUNT_RS_IP", "WLAN1_VAP0_ACCOUNT_RS_PORT", "WLAN1_VAP0_ACCOUNT_RS_PASSWORD"},
		 {"WLAN1_VAP1_ACCOUNT_RS_IP", "WLAN1_VAP1_ACCOUNT_RS_PORT", "WLAN1_VAP1_ACCOUNT_RS_PASSWORD"},
		 {"WLAN1_VAP2_ACCOUNT_RS_IP", "WLAN1_VAP2_ACCOUNT_RS_PORT", "WLAN1_VAP2_ACCOUNT_RS_PASSWORD"},
		 {(char *)0, (char *)0, (char *)0}}
	};

	tmp[0] = 0;
	memset(&wlan_rate[0], 0, sizeof(wlan_rate));
	for (j = 0; j < 2; j++) {
		for (i = 0; i < 4; i++) {
			wlan_rate[j][i].ratelimit = 100;
		}
	}
	sprintf(&tmp[0], "%s", &ldap_p->value[0]);
	sprintf(&tmp1[0], "%s", &ldap_p->value[0]);

	switch (id) {
	case WLAN_DISABLED:
	case SSID_ENABLE:
	case HIDDEN_SSID:
	case DESIGNATED_RATE_LIMIT_SSID:
	case RADIUS_AUTH_SSID:
	case MAC_AUTH_SSID:
	case RADIUS_SVR_INFO:
	case ACCOUNT_SVR_INFO:
	case WIFI_5G_DISABLED:
	case SSID_5G_ENABLE:
	case HIDDEN_5G_SSID:
	case DESIGNATED_5G_RATE_LIMIT_SSID:
	case RADIUS_AUTH_5G_SSID:
	case MAC_AUTH_5G_SSID:
	case RADIUS_SVR_5G_INFO:
	case ACCOUNT_SVR_5G_INFO:
		/*
		   SK_WiFixxx(main), anyway(vap0), SK_VoIP(vap1), T wifi home(vap2)
		 */
		if ((value_index = notify_value_index(tmp1)) < 0) {
			if ((id != SSID_ENABLE) && (id != HIDDEN_SSID) &&
			    (id != SSID_5G_ENABLE) && (id != HIDDEN_5G_SSID))
				return 0;
		}

		for (idx = 1, p = strtok_r(&tmp[0], WLAN_DELIM, &saveptr); p;
		     p = strtok_r(NULL, WLAN_DELIM, &saveptr), wlan_idx = -1, idx++) {
			match = 0;
			ydespaces(p);

			if (id >= WLAN_DISABLED && id <= ACCOUNT_SVR_INFO) {
				wlan_radio = 1;
			} else {
				wlan_radio = 0;
			}

			if (id == WLAN_DISABLED || id == WIFI_5G_DISABLED) {
				wlan_idx = 0;
				wlan_enable[wlan_radio][wlan_idx].enable = safe_atoi(ldap_p->value, 0);
				continue;
			}

			for (iw = 0; iw < 4; iw++) {
				if (!strcasecmp(p, wlan_ssid_snmp[wlan_radio][iw])) {
					wlan_idx = iw;
					break;
				}
			}

			if (wlan_idx >= 0 && wlan_idx < 4) {
				/*if (id == WLAN_DISABLED || id == WIFI_5G_DISABLED) {
				   wlan_idx=0;
				   wlan_enable[wlan_radio][wlan_idx].enable = safe_atoi(ldap_p->value, 0);
				   }
				   else */
				if (id == SSID_ENABLE || id == SSID_5G_ENABLE) {
					wlan_enable[wlan_radio][wlan_idx].enable = 1;
				} else if (id == HIDDEN_SSID || id == HIDDEN_5G_SSID) {
					wlan_hidden[wlan_radio][wlan_idx].enable = 1;
				} else if (id == DESIGNATED_RATE_LIMIT_SSID || id == DESIGNATED_5G_RATE_LIMIT_SSID) {
					wlan_rate[wlan_radio][wlan_idx].setup = 1;
					wlan_rate[wlan_radio][wlan_idx].seq_f = idx;
				} else if (id == RADIUS_AUTH_SSID || id == RADIUS_AUTH_5G_SSID) {
					wlan_auth[wlan_radio][wlan_idx].setup_f = 1;
				} else if (id == MAC_AUTH_SSID || id == MAC_AUTH_5G_SSID) {
					if (!((wlan_auth[wlan_radio][wlan_idx].setup_f & 0xf) & 0x1)) {
						wlan_auth[wlan_radio][wlan_idx].setup_f = 2;
					}
				} else if (id == RADIUS_SVR_INFO || id == RADIUS_SVR_5G_INFO) {
					wlan_auth[wlan_radio][wlan_idx].setup_f |= 4;
					wlan_auth[wlan_radio][wlan_idx].radius.seq_f = idx;
				} else if (id == ACCOUNT_SVR_INFO || id == ACCOUNT_SVR_5G_INFO) {
					wlan_auth[wlan_radio][wlan_idx].setup_f |= 8;
					wlan_auth[wlan_radio][wlan_idx].account.seq_f = idx;
				}
				continue;
			}
			if (value_index > idx)
				continue;

			for (j = 0; j < 4; j++) {
				if (id == DESIGNATED_RATE_LIMIT_SSID || id == DESIGNATED_5G_RATE_LIMIT_SSID) {
					if ((wlan_rate[wlan_radio][j].seq_f == rv) && wlan_rate[wlan_radio][j].setup) {
						wlan_rate[wlan_radio][j].setup = 0;
						if (is_digits(&p[0], strlen(&p[0]), 0)) {
							ratelimit = strtoul(&p[0], NULL, 10);
							if (WLAN_IS_RATELIMIT(ratelimit))
								wlan_rate[wlan_radio][j].ratelimit = ratelimit;
						}
						break;
					}
				} else if (id == RADIUS_SVR_INFO || id == RADIUS_SVR_5G_INFO) {
					set_flag = wlan_auth[wlan_radio][j].setup_f & 0xf;
					if ((wlan_auth[wlan_radio][j].radius.seq_f == rv) && (set_flag & (0x5 | 0x6))) {
						if (!wlan_auth[wlan_radio][j].radius.srv_addr.s_addr) {
							if (inet_aton(p, &ip) && ip.s_addr != 0
							    && ip.s_addr != (in_addr_t)-1) {
								wlan_auth[wlan_radio][j].radius.srv_addr = ip;
							}
							rv--;
						} else if (!wlan_auth[wlan_radio][j].radius.port) {
							if (is_digits(p, strlen(p), 0))
								wlan_auth[wlan_radio][j].radius.port = strtoul(p, NULL, 10);
							rv--;
						} else if (wlan_auth[wlan_radio][j].radius.passwd[0] == 0) {
							sprintf(wlan_auth[wlan_radio][j].radius.passwd, "%s", p);
							wlan_auth[wlan_radio][j].radius.seq_f = 0;
						} else {
							wlan_auth[wlan_radio][j].radius.seq_f = 0;
						}
						break;
					}
				} else if (id == ACCOUNT_SVR_INFO || id == ACCOUNT_SVR_5G_INFO) {
					set_flag = wlan_auth[wlan_radio][j].setup_f & 0xf;
					if ((wlan_auth[wlan_radio][j].account.seq_f == rv) && (set_flag & (0x9 | 0xa))) {
						if (!wlan_auth[wlan_radio][j].account.srv_addr.s_addr) {
							if (inet_aton(p, &ip) && (ip.s_addr != 0)
							    && (ip.s_addr != (in_addr_t)-1)) {
								wlan_auth[wlan_radio][j].account.srv_addr = ip;
							}
							rv--;
						} else if (!wlan_auth[wlan_radio][j].account.port) {
							if (is_digits(p, strlen(p), 0))
								wlan_auth[wlan_radio][j].account.port = strtoul(p, NULL, 10);
							rv--;
						} else if (wlan_auth[wlan_radio][j].account.passwd[0] == 0) {
							sprintf(wlan_auth[wlan_radio][j].account.passwd, "%s", p);
							wlan_auth[wlan_radio][j].account.seq_f = 0;
						} else {
							wlan_auth[wlan_radio][j].account.seq_f = 0;
						}
						break;
					}
				}
			}
			rv++;

			continue;
		}
		for (i = 0; i < 4; i++) {
			if (flag & FLG_APMIB) {
				if (id >= WLAN_DISABLED && id <= ACCOUNT_SVR_INFO) {
					wlan_radio = 1;
				} else {
					wlan_radio = 0;
				}
				if (id == WLAN_DISABLED || id == WIFI_5G_DISABLED) {
					if (i == 0) {
						mib_name = wlan_enable[wlan_radio][i].mib_name;
						mib_value = WLAN_SSID_ACTIVE(!wlan_enable[wlan_radio][i].enable);
					}
				} else if (id == SSID_ENABLE || id == SSID_5G_ENABLE) {
					if (i == 0)
						continue;
					mib_name = wlan_enable[wlan_radio][i].mib_name;
					mib_value = WLAN_SSID_ACTIVE(wlan_enable[wlan_radio][i].enable);
				} else if (id == HIDDEN_SSID || id == HIDDEN_5G_SSID) {
					mib_name = wlan_hidden[wlan_radio][i].mib_name;
					mib_value = WLAN_SSID_ACTIVE(!wlan_hidden[wlan_radio][i].enable);
				} else if (id == RADIUS_SVR_INFO || id == RADIUS_SVR_5G_INFO) {
					/*server ip */
					if (wlan_auth[wlan_radio][i].radius.srv_addr.s_addr != 0) {
						mib_name = wlan_radius_name[wlan_radio][i].server;
						mib_value = inet_ntoa(wlan_auth[wlan_radio][i].radius.srv_addr);
						restart |= apply_ldapcfg_apmib(mib_name, mib_value, flag);
					}
					/*server port */
					if (wlan_auth[wlan_radio][i].radius.port > 0) {
						mib_name = wlan_radius_name[wlan_radio][i].port;
						sprintf(buf, "%d", wlan_auth[wlan_radio][i].radius.port);
						mib_value = buf;
						restart |= apply_ldapcfg_apmib(mib_name, mib_value, flag);
					}
					/*server passwd */
					if (wlan_auth[wlan_radio][i].radius.passwd[0] != 0) {
						mib_name = wlan_radius_name[wlan_radio][i].passwd;
						mib_value = wlan_auth[wlan_radio][i].radius.passwd;
						restart |= apply_ldapcfg_apmib(mib_name, mib_value, flag);
					}
					continue;
				} else if (id == ACCOUNT_SVR_INFO || id == ACCOUNT_SVR_5G_INFO) {
					/*server ip */
					if (wlan_auth[wlan_radio][i].account.srv_addr.s_addr != 0) {
						mib_name = wlan_account_name[wlan_radio][i].server;
						mib_value = inet_ntoa(wlan_auth[wlan_radio][i].account.srv_addr);
						restart |= apply_ldapcfg_apmib(mib_name, mib_value, flag);
					}
					/*server port */
					if (wlan_auth[wlan_radio][i].account.port > 0) {
						mib_name = wlan_account_name[wlan_radio][i].port;
						sprintf(buf, "%d", wlan_auth[wlan_radio][i].account.port);
						mib_value = buf;
						restart |= apply_ldapcfg_apmib(mib_name, mib_value, flag);
					}
					/*server passwd */
					if (wlan_auth[wlan_radio][i].account.passwd[0] != 0) {
						mib_name = wlan_account_name[wlan_radio][i].passwd;
						mib_value = wlan_auth[wlan_radio][i].account.passwd;
						restart |= apply_ldapcfg_apmib(mib_name, mib_value, flag);
					}
					continue;
				}
				if (id == RADIUS_AUTH_SSID || id == MAC_AUTH_SSID || id == RADIUS_AUTH_5G_SSID || id == MAC_AUTH_5G_SSID)
					continue;

				restart |= apply_ldapcfg_apmib(mib_name, mib_value, flag);
			}
			if (flag & FLG_DVNV) {
				if (id == DESIGNATED_RATE_LIMIT_SSID || id == DESIGNATED_5G_RATE_LIMIT_SSID) {
					if (i == 0) {
						sprintf(&nvram_name_tx[0], "WLAN%d_TX_RESTRICT", wlan_radio);
						sprintf(&nvram_name_rx[0], "WLAN%d_RX_RESTRICT", wlan_radio);
					} else {
						sprintf(&nvram_name_tx[0], "WLAN%d_VAP%d_TX_RESTRICT", wlan_radio, i - 1);
						sprintf(&nvram_name_rx[0], "WLAN%d_VAP%d_RX_RESTRICT", wlan_radio, i - 1);
					}

					if (WLAN_IS_RATELIMIT(wlan_rate[wlan_radio][i].ratelimit)) {
						sprintf(rate_limit, "%d", wlan_rate[wlan_radio][i].ratelimit);
						restart |= apply_ldapcfg_nvram(nvram_name_tx, rate_limit, flag);
						restart |= apply_ldapcfg_nvram(nvram_name_rx, rate_limit, flag);
					}
				}
			}
		}
		break;
	default:
		break;
	}
	return restart;
}

static int syslog_setup(char *name, struct ldap_item *ldap_p)
{
	int i;
	int id = ldap_p->id;
	char tmp[128];
	int restart = 0;

	sprintf(&tmp[0], "%s", &ldap_p->value[0]);

	if (tmp[0] == 0 || !strcmp(&tmp[0], "0.0.0.0")) {
		restart |= apply_ldapcfg_apmib("REMOTELOG_ENABLED", "0", FLG_REBOOT);
	} else {
		restart |= apply_ldapcfg_apmib("REMOTELOG_ENABLED", "1", FLG_REBOOT);
	}
	restart |= apply_ldapcfg_nvram("REMOTELOG_SERVER", tmp, ldap_p->flag);

	return restart;
}

/*
exam)
port_nego=1|2|3|4, auto|auto|auto|auto
port_speed=1|2|3|4, 100|100|100|100
port_duplex=1|2|3|4, auto|auto|auto|full
port_enable=1|2|3|4, Y|Y|N|Y
port_rate_limit=1|2|3|4, 100|100|100|100
*/
#define LAN_DELIM  " |,\r\n\t"
static void lan_setup(char *name, struct ldap_item *ldap_p)
{
	int i;
	int id = ldap_p->id;
	int idx = -1;
	char *p, *saveptr;
	char tmp[128];

	sprintf(&tmp[0], "%s", &ldap_p->value[0]);
	switch (id) {
	case PORT_NEGO:
	case PORT_SPEED:
	case PORT_DUPLEX:
	case PORT_ENABLE:
	case PORT_RATE_LIMIT:
		for (p = strtok_r(tmp, LAN_DELIM, &saveptr); p; p = strtok_r(NULL, LAN_DELIM, &saveptr), idx = -1) {
			ydespaces(p);
			if (!strcasecmp(p, "1")) {
				idx = 0;
			} else if (!strcasecmp(p, "2")) {
				idx = 1;
			} else if (!strcasecmp(p, "3")) {
				idx = 2;
			} else if (!strcasecmp(p, "4")) {
				idx = 3;
			}
			if (idx >= 0 && idx < 4) {
				if (id == PORT_NEGO) {
					lan[idx].auto_nego.set = 1;
				} else if (id == PORT_SPEED) {
					lan[idx].speed.set = 1;
				} else if (id == PORT_DUPLEX) {
					lan[idx].duplex.set = 1;
				} else if (id == PORT_ENABLE) {
					lan[idx].power_off.set = 1;
				} else if (id == PORT_RATE_LIMIT) {
					lan[idx].rate_limit.set = 1;
				}
				continue;
			}
			for (i = 0; i < 4; i++) {
				if (id == PORT_NEGO) {
					if (lan[i].auto_nego.set) {
						if (!strcasecmp(p, "auto"))
							lan[i].auto_nego.val = 1;
						else if (!strcasecmp(p, "force"))
							lan[i].auto_nego.val = 2;
						lan[i].auto_nego.set = 0;
						break;
					}
				} else if (id == PORT_SPEED) {
					if (lan[i].speed.set) {
						if (is_digits(p, strlen(p), 0))
							lan[i].speed.val = strtoul(p, NULL, 10);
						lan[i].speed.set = 0;
						break;
					}
				} else if (id == PORT_DUPLEX) {
					if (lan[i].duplex.set) {
						if (!strcasecmp(p, "auto"))
							lan[i].duplex.val = 3;
						else if (!strcasecmp(p, "full"))
							lan[i].duplex.val = 2;
						else if (!strcasecmp(p, "half"))
							lan[i].duplex.val = 1;

						lan[i].duplex.set = 0;
						break;
					}
				} else if (id == PORT_ENABLE) {
					if (lan[i].power_off.set) {
						lan[i].power_off.val = IS_NO(p[0]);
						lan[i].power_off.set = 0;
						break;
					}
				} else if (id == PORT_RATE_LIMIT) {
					if (lan[i].rate_limit.set) {
						if (is_digits(&p[0], strlen(p), 0)) {
							lan[i].rate_limit.val = strtoul(&p[0], NULL, 10);
						}
						lan[i].rate_limit.set = 0;
						break;
					}
				}
			}
		}
		break;
	default:
		break;
	}
}

static int apply_lan_setup(void)
{
	int i;
	char lan_intf[80];
	char st_info[80];
	int restart = 0;
	int n = 0;
	char qos_name[80], qos_i[80], qos_o[80];
	char *p;
	int phy_down = 0;

	for (i = 0; i < 4; i++, n = 0) {
		sprintf(&lan_intf[0], "x_port_%d_config", i);
		st_info[0] = 0;
		if (lan[i].auto_nego.val > 0) {
			//n = sprintf(&st_info[0], "%s", (lan[i].auto_nego.val==1)? "auto":"force");
			if (lan[i].power_off.val > 0) {
				n += sprintf(&st_info[n], "%s_%s", (lan[i].power_off.val == 1) ? "down" : "up",
					     (lan[i].auto_nego.val == 1) ? "auto" : "force");
			}
			if (lan[i].auto_nego.val == 2) {	//nego force
				if (lan[i].duplex.val > 0 && lan[i].duplex.val <= 3) {
					n += sprintf(&st_info[n], "_duplex_%s", (lan[i].duplex.val == 2) ? "full" : "half");
				}
				if (lan[i].speed.val == 10 || lan[i].speed.val == 100 || lan[i].speed.val == 1000) {
					//n += sprintf(&st_info[n], "_speed_%s", (lan[i].speed.val==10)? "10":"100");
					n += sprintf(&st_info[n], "_speed_%d", lan[i].speed.val);
				}
			}
			n += sprintf(&st_info[n], "_-rxpause_txpause");
			if (n > 0)
				restart |= apply_ldapcfg_nvram(lan_intf, st_info, FLG_REBOOT);
		}
		if (lan[i].rate_limit.val >= 0 && lan[i].rate_limit.val <= 1000) {
			sprintf(&qos_name[0], "x_QOS_RATE_ENABLE_%d", i);
			sprintf(&qos_i[0], "x_QOS_RATE_I_%d", i);
			sprintf(&qos_o[0], "x_QOS_RATE_O_%d", i);

			st_info[0] = 0;
			sprintf(&st_info[0], "%d", (lan[i].rate_limit.val * 1024));
			if (lan[i].rate_limit.val == 0) {
				restart |= apply_ldapcfg_nvram(qos_name, "0", FLG_REBOOT);
			} else {
				restart |= apply_ldapcfg_nvram(qos_name, "1", FLG_REBOOT);
			}
			restart |= apply_ldapcfg_nvram(qos_i, st_info, FLG_REBOOT);
			restart |= apply_ldapcfg_nvram(qos_o, st_info, FLG_REBOOT);
		}
	}
	return restart;
}

#define SNMP_DELIM  ":\r\n\t"
static int apply_server_port_setup(struct ldap_item *ldap_p)
{
	int i;
	char *saveptr;
	char *name, *server, *port;
	int id = ldap_p->id;
	char val[128];
	char *p;
	int restart = 0;
	int port_setup = 0;

	if (id == x_WIFI_TRAP_SERVER) {
		server = "x_WIFI_TRAP_SERVER";
		port = "x_WIFI_TRAP_PORT";
	} else if (id == HP_SVR_IP_PORT) {
		server = "x_holepunch_cserver";
		port = "x_holepunch_cport";
	} else
		return restart;

	val[0] = 0;
	sprintf(&val[0], "%s", &ldap_p->value[0]);
	for (i = 0, p = strtok_r(&val[0], SNMP_DELIM, &saveptr); p && (p[0] != 0);
	     p = strtok_r(NULL, SNMP_DELIM, &saveptr), i++) {
		ydespaces(p);
		if (i == 0) {	//server
			name = server;
		} else if (i == 1) {	//port
			name = port;
			port_setup = 1;
		} else
			break;
		restart |= apply_ldapcfg_nvram(name, p, ldap_p->flag);
	}
	if (port_setup == 0) {
		if (id == x_WIFI_TRAP_SERVER) {
			nvram_set(port, "162");
			//nvram_commit();
		}
		if (id == HP_SVR_IP_PORT) {
			nvram_set(port, "10219");
			//nvram_commit();
		}
	}

	return restart;
}

static void lan_dhcp_setup(char *name, struct ldap_item *ldap_p)
{
	int id = ldap_p->id;
	char val[128];

	if (ldap_p->value[0] == 0)
		return;

	val[0] = 0;
	sprintf(&val[0], "%s", &ldap_p->value[0]);
	if (id == DHCP_CLIENT_START)
		inet_aton(val, &ippool[0]);
	else if (id == DHCP_CLIENT_END)
		inet_aton(val, &ippool[1]);
}

static int apply_lan_dhcp_setup(void)
{
	char buf[64];
	struct in_addr ip, netmask, subnet, tmp1, tmp2;
	int status;
	int restart = 0;

	if (!ippool[0].s_addr || !ippool[1].s_addr || (ippool[0].s_addr > ippool[1].s_addr))
		return 0;

	fls_mibget("DHCP_CLIENT_START", buf, sizeof(buf));
	if (!inet_aton(buf, &tmp1))
		return 0;

	fls_mibget("DHCP_CLIENT_END", buf, sizeof(buf));
	if (!inet_aton(buf, &tmp2))
		return 0;

	if (ippool[0].s_addr == tmp1.s_addr && ippool[1].s_addr == tmp2.s_addr)
		return 0;

	fls_mibget("IP_ADDR", buf, sizeof(buf));
	if (!inet_aton(buf, &ip))
		return 0;

	fls_mibget("SUBNET_MASK", buf, sizeof(buf));
	if (!inet_aton(buf, &netmask))
		return 0;

	if (!ip.s_addr || ip.s_addr == (in_addr_t)-1 || !netmask.s_addr || netmask.s_addr == (in_addr_t)-1)
		return 0;

	subnet.s_addr = ip.s_addr & netmask.s_addr;
	if (((ippool[0].s_addr & netmask.s_addr) != subnet.s_addr) ||
	    ((ippool[1].s_addr & netmask.s_addr) != subnet.s_addr) ||
	    (ippool[0].s_addr == subnet.s_addr) ||
	    (ippool[0].s_addr == (subnet.s_addr | ~netmask.s_addr)) ||
	    (ippool[1].s_addr == (subnet.s_addr | ~netmask.s_addr)))
		return 0;

	if (ippool[0].s_addr <= ip.s_addr && ippool[1].s_addr >= ip.s_addr)
		return 0;
/*
    if (!yexecl(NULL, "flash set DHCP_CLIENT_START %s", inet_ntoa(ippool[0])))
        restart = 1;
    if (!yexecl(NULL, "flash set DHCP_CLIENT_END %s", inet_ntoa(ippool[1])))
        restart = 1;
*/
	if (!nvram_set("DHCP_CLIENT_START", inet_ntoa(ippool[0]))) {
		//nvram_commit();
		restart = 1;
	}
	if (!nvram_set("DHCP_CLIENT_END", inet_ntoa(ippool[1]))) {
		//nvram_commit();
		restart = 1;
	}
	LDAP_PRINT("Diff apmib dhcp pool changed(%s~%s) - set restart.\n", inet_ntoa(ippool[0]), inet_ntoa(ippool[1]));

	return (restart);
}

static int apply_ldapcfg_system(void)
{
	int i;
	struct ldap_item *p;
	int total = ldap_cfg.entry;
	char *syscfgName;
	FILE *fp = NULL, *fp_a = NULL;
	int restart = 0;
	int save_cfg;

	save_cfg = safe_atoi(nvram_get("ldap_save"), 1);
	fp_a = fopen("/var/ldap_autoreboot", "w");
	if (save_cfg && (fp = fopen("/var/ldap_cfg", "w")))
		fprintf(fp, "*entry = %d \n", total);
	for (i = 0; i < total; i++) {
		p = &ldap_cfg.item[i];
		syscfgName = get_id_name_ldapcfg_map(p->id);

		if (p->flag & FLG_DVNV) {
			if (p->id == x_WIFI_TRAP_SERVER || p->id == HP_SVR_IP_PORT) {
				restart |= apply_server_port_setup(p);
			} else if (p->id == DESIGNATED_RATE_LIMIT_SSID || p->id == DESIGNATED_5G_RATE_LIMIT_SSID) {
				restart |= apply_wlan_setup(syscfgName, p);
			} else if (p->id >= PORT_NEGO && p->id <= PORT_RATE_LIMIT) {
				lan_setup(syscfgName, p);
			} else if (p->id == syslog_server_url) {
				restart |= syslog_setup(syscfgName, p);
			} else {
				restart |= apply_ldapcfg_nvram(syscfgName, p->value, p->flag);
			}
		} else if (p->flag & FLG_APMIB) {
			/*if ( (p->id >= WLAN_DISABLED && p->id <= WIFI_5G_DISABLED) ||
			   (p->id >= SSID_ENABLE && p->id <= HIDDEN_SSID) ||
			   (p->id >= SSID_5G_ENABLE && p->id <= HIDDEN_5G_SSID) ||
			   (p->id >= RADIUS_AUTH_5G_SSID && p->id <= ACCOUNT_SVR_5G_INFO) ||
			   (p->id >= RADIUS_AUTH_SSID && p->id <= ACCOUNT_SVR_INFO) ) { */
			if (p->id >= WLAN_DISABLED && p->id <= ACCOUNT_SVR_5G_INFO) {
				restart |= apply_wlan_setup(syscfgName, p);
			} else if (p->id == DHCP_CLIENT_START || p->id == DHCP_CLIENT_END) {
				lan_dhcp_setup(syscfgName, p);
			} else {
				restart |= apply_ldapcfg_apmib(syscfgName, p->value, p->flag);
			}
		}

		if (p->id >= x_auto_reboot_on_idle && p->id <= x_auto_hour_range) {
			if (fp_a) {
				ldapcfg_save_to_file(fp_a, syscfgName, p->value);
			}
		}

		if (fp)
			ldapcfg_save_to_file(fp, syscfgName, p->value);
	}
	restart |= apply_lan_setup();
	restart |= apply_lan_dhcp_setup();

	if (fp_a)
		fclose(fp_a);

	if (fp)
		fclose(fp);

	return restart;
}

int main(void)
{
	struct fwstat fbuf;
	char buffer[2560];
	int exp, status;
	int do_reboot;
	char tmp[30];
	time_t t;
	int ldap_enable;
	version_t realver;

	ldap_enable = safe_atoi(nvram_get("x_ldap_enabled"), 0);

	if (!ldap_enable) {
		printf("ldap setup: disable...\n");
		return 0;
	}
	signal(SIGTERM, sig_term);

	nvram_get_r_def("ldap_dbg", tmp, sizeof(tmp), "0");
	ldap_debug_enabled = strtoul(tmp, NULL, 10);

	if (initenv(&fw_info)) {
		LDAP_PRINT("Environment's Insufficient\n");
		sig_term(0);
	}
	init_ldap_cfg();

	int_wlan_ssid_name();
	syslog(LOG_INFO, "[LDAP CFG] 시작 \n");
	do {
		status = 0;
		memset(&fbuf, 0, sizeof(fbuf));
		fbuf.fmem = buffer;
		fbuf.caplen = 2560;
		if (!do_wget(&fbuf, &tries, MAX_TIMEO, fw_info.confurl)) {
			fbuf.fmem[fbuf.rcvlen] = '\0';
			do_reboot = 0;
			if (parse_config(&fw_info, fbuf.fmem, &do_reboot)) {
				LDAP_PRINT("parse_config needs %s\n", (do_reboot) ? "REBOOT" : "NO reboot");
				if (fw_info.new.all && newer_version(&fw_info.new, &fw_info.cur)) {
					char *mm;
					mm = mmap(NULL, MAX_FWSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
					if (mm == MAP_FAILED) {
						perror("mmap");
						sig_term(0);
					}
					exp = 0;
					do {
						memset(&fbuf, 0, sizeof(fbuf));
						fbuf.fmem = mm;
						fbuf.caplen = MAX_FWSIZE;
						if (!build_url(buffer, fw_info.binpath, fw_info.binname) &&
						    !do_wget(&fbuf, &exp, MAX_TIMEO, buffer)) {
							LDAP_PRINT("image length %d\n", fbuf.rcvlen);
							fw_parse_bootline(&fbuf.blnfo);
							status = fw_validate(&fbuf);
							if (status == 0) {
								memset(&realver, 0, sizeof(realver));
								realver.i.major = (fbuf.version >> 14) & 3;
								realver.i.minor = (fbuf.version >> 7) & 0x7f;
								realver.i.conf = fbuf.version & 0x7f;
							}
							if (!status &&
							    ({ status = -ESAMEVERS; 1; }) &&
							    newer_version(&realver, &fw_info.cur) &&
							    !(status = fw_dualize(&fbuf))) {
								ifconfig("br0", 0, NULL, NULL);
								status = fw_write(&fbuf, NULL, NULL);
								if (!status) {
									syslog(LOG_INFO,
									       "[LDAP CFG]업그레이드 성공.(v%d.%d.%d->v%d.%d.%d) 단말 재부팅.\n",
									       fw_info.cur.i.major, fw_info.cur.i.minor,
									       fw_info.cur.i.conf, fw_info.new.i.major,
									       fw_info.new.i.minor, fw_info.new.i.conf);
									munmap(mm, MAX_FWSIZE);
									mm = MAP_FAILED;
									t = time(NULL);
									strftime(buffer, sizeof(buffer), "%F %H:%M:%S",
										 localtime(&t));
									//nvram_set("swms_upgrade_time", buffer);
									nvram_commit();
									sleep(5);
									sys_reboot();
								} else
									ifconfig("br0", IFUP, NULL, NULL);
							}
							syslog(LOG_INFO,
							       "[LDAP CFG]업그레이드 실패.(v%d.%d.%d->v%d.%d.%d)\n",
							       fw_info.cur.i.major, fw_info.cur.i.minor, fw_info.cur.i.conf,
							       fw_info.new.i.major, fw_info.new.i.minor, fw_info.new.i.conf);
							LDAP_PRINT("%s\n", fw_strerror(status));
						} else
							status = -EGETFW;
					} while (exp < MAX_TRY && (status != -ESAMEVERS));

					if (mm != MAP_FAILED)
						munmap(mm, MAX_FWSIZE);
				} else {
					syslog(LOG_INFO,
					       "[LDAP CFG]업그레이드 조건에 해당하지 않음.(AP:v%d.%d.%d|Server:v%d.%d.%d)\n",
					       fw_info.cur.i.major, fw_info.cur.i.minor, fw_info.cur.i.conf,
					       fw_info.new.i.major, fw_info.new.i.minor, fw_info.new.i.conf);
					status = -ESAMEVERS;
				}

				if (do_reboot) {
					nvram_commit();
					sleep(5);
					sys_reboot();
				}
			} else {
				if (!ldap_cfg.normal_down_cfg) {
					status = -EINVALCONF;
				} else if (!fw_info.upgrade_keep_going) {
					LDAP_PRINT("CAN'T GOING UPGRADE by CFG\n");
				}

				if (do_reboot) {
					nvram_commit();
					sys_reboot();
				}
			}
		} else {
			status = -EGETCONF;
		}
		LDAP_PRINT("%s\n", fw_strerror(status));

		fw_info.quiet = 1;
	} while (fw_info.background);

	return 0;
}
