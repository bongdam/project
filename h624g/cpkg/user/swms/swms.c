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
#include "nvram_mib/nvram_mib.h"

/* APNRTL-223 */
#define NETCFG_DISABLE  1

#define SKBB_DEF_URL "iptvsh-mgnt.skbroadband.com:12380"

#define SKBB_DEF_CFG SYS_NAME "_config.txt"
#define SKT_DEF_CFG SYS_NAME "_home_config.txt"

#define SKBB_DEF_FIRM_URL "iptvsh-mgnt.skbroadband.com:12380"
#define SKBB_DEF_PREFIX "files"

#define MAX_TRY     4
#define MAX_TIMEO   4000
#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif

typedef union {
	unsigned int all;
	struct {
		unsigned int major:8;
		unsigned int minor:8;
		unsigned int conf:8;
		unsigned int:8;
	} i;
} version_t;

struct fwinfo {
	char confurl[128];	/* including file name (ex) http://config.skbroadband.com/config */
	char binpath[128];	/* image server */
	char binname[80];	/* image file name */
	version_t cur, new;
	int background, quiet;
};

#define TYPE_MASK   0x7

enum { TYPE_STRING, TYPE_INT, TYPE_IPV4, TYPE_PORT, TYPE_ONOFF };

enum {
	FLG_REBOOT = (1 << 3),	/* Need reboot */
	FLG_NILNOK = (1 << 4),	/* Can not be null(nil) */
	FLG_INETATON = (1 << 5),	/* Neither 0.0.0.0 nor 255.255.255.255 */
	FLG_INANY = (1 << 6)	/* if not specified, consider as "0.0.0.0" */
};

typedef struct variable_s {
	const char *name;
	int (*setvar) (struct variable_s *, const char *, const char *);
	void *data;
	unsigned int flgs;
} variable;

#if !NETCFG_DISABLE
static int ippool_preset(struct variable_s *, const char *, const char *);
#endif
static int nvram_setvar(struct variable_s *, const char *, const char *);
static int fls_setvar(struct variable_s *, const char *, const char *);
static int fls_setvar2(struct variable_s *, const char *, const char *);
static int fwinfo_setvar(struct variable_s *, const char *, const char *);
static int dv_variable(struct variable_s *v, const char *name, const char *value);

#if NETCFG_DISABLE
#define MIBLIST "WLAN0_VAP2_RS_IP "\
				"WLAN0_VAP2_RS_PORT "\
				"WLAN0_VAP2_RS_PASSWORD "\
				"WLAN1_VAP2_RS_IP "\
				"WLAN1_VAP2_RS_PORT "\
				"WLAN1_VAP2_RS_PASSWORD "\
				"SCRLOG_ENABLED "\
				"REMOTELOG_ENABLED "\
				"REMOTELOG_SERVER "\
				"IGMP_PROXY_DISABLED "\
				"IP_ADDR "\
				"SUBNET_MASK"
#else
#define MIBLIST "WLAN0_WLAN_DISABLED "\
				"WLAN1_WLAN_DISABLED "\
				"WLAN0_VAP2_RS_IP "\
				"WLAN0_VAP2_RS_PORT "\
				"WLAN0_VAP2_RS_PASSWORD "\
				"WLAN1_VAP2_RS_IP "\
				"WLAN1_VAP2_RS_PORT "\
				"WLAN1_VAP2_RS_PASSWORD "\
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

static struct fwinfo fw_info;
static int tries;
static char flsbuffer[1024];
static struct in_addr ippool[2];
static int dv_force_upgrade;
static int led_flag;
static int verbose;
static variable vartbl[] = {
	{"Conf_Server", nvram_setvar, (void *)"x_autoup_domain", TYPE_STRING},
	{"Firmware_Server", fwinfo_setvar, NULL, TYPE_STRING},
	{"Trap_Server", nvram_setvar, (void *)"x_SNMP_TRAP_SERVER", TYPE_STRING | FLG_REBOOT},
	{"Syslog_Server", fls_setvar2, NULL, TYPE_IPV4 | FLG_REBOOT},
	{"Firmware_File", fwinfo_setvar, NULL, TYPE_STRING},
	{"Firmware_Version", fwinfo_setvar, NULL, TYPE_STRING},
	{"Community_Get", nvram_setvar, (void *)"x_SNMP_GET_COMMUNITY", TYPE_STRING | FLG_NILNOK | FLG_REBOOT},
	{"Community_Set", nvram_setvar, (void *)"x_SNMP_SET_COMMUNITY", TYPE_STRING | FLG_NILNOK | FLG_REBOOT},
	{"Community_Trap", nvram_setvar, (void *)"x_SNMP_TRAP_COMMUNITY", TYPE_STRING | FLG_NILNOK | FLG_REBOOT},
	//{ "Trap_Interval", null_setvar, NULL, NULL, FALSE },
	{"Radius_Server_IP", fls_setvar, (void *)"WLAN1_VAP2_RS_IP", TYPE_IPV4 | FLG_INANY | FLG_REBOOT},
	{"Radius_Server_Port", fls_setvar, (void *)"WLAN1_VAP2_RS_PORT", TYPE_PORT | FLG_NILNOK | FLG_REBOOT},
	{"Radius_Server_Password", fls_setvar, (void *)"WLAN1_VAP2_RS_PASSWORD", TYPE_STRING | FLG_NILNOK | FLG_REBOOT},
	{"Radius_Server_5g_IP", fls_setvar, (void *)"WLAN0_VAP2_RS_IP", TYPE_IPV4 | FLG_INANY | FLG_REBOOT},
	{"Radius_Server_5g_Port", fls_setvar, (void *)"WLAN0_VAP2_RS_PORT", TYPE_PORT | FLG_NILNOK | FLG_REBOOT},
	{"Radius_Server_5g_Password", fls_setvar, (void *)"WLAN0_VAP2_RS_PASSWORD", TYPE_STRING | FLG_NILNOK | FLG_REBOOT},
#if !NETCFG_DISABLE
	{"DNS1", fls_setvar, (void *)"DNS1", TYPE_IPV4 | FLG_INANY | FLG_REBOOT},
	{"DNS2", fls_setvar, (void *)"DNS2", TYPE_IPV4 | FLG_INANY | FLG_REBOOT},
	{"DHCP_IPPool_Start_IP", ippool_preset, (void *)&ippool[0], TYPE_IPV4 | FLG_INETATON | FLG_REBOOT},
	{"DHCP_IPPool_End_IP", ippool_preset, (void *)&ippool[1], TYPE_IPV4 | FLG_INETATON | FLG_REBOOT},
	{"AP_Mode", fls_setvar2, (void *)"WLAN1_WLAN_DISABLED", TYPE_ONOFF | FLG_NILNOK | FLG_REBOOT},
	{"AP_Mode_5g", fls_setvar2, (void *)"WLAN0_WLAN_DISABLED", TYPE_ONOFF | FLG_NILNOK | FLG_REBOOT},
#endif
	{"IGMP", fls_setvar2, (void *)"IGMP_PROXY_DISABLED", TYPE_INT | FLG_NILNOK | FLG_REBOOT},
	{"ekqh_release_time", dv_variable, NULL, TYPE_STRING},	//using manufacture upgrading.
	{"ekqhfldzm_rev", dv_variable, NULL, TYPE_STRING | FLG_REBOOT},
	{NULL, NULL, NULL, 0}
};

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
	ystrtrim(buf, ":/ \t\r\n");
	if (buf[0]) {
		sprintf(url, "http://%s/", buf);
		strcpy(buf, fname);
		ystrtrim(buf, "/ \t\r\n");
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

	buf[0] = '\0';
	while ((p = read_line(p, line, sizeof(line)))) {
		eq = strchr(line, '=');
		if (eq) {
			*eq++ = '\0';
			ydespaces(line);
			ystrtrim(eq, " \t\r\n\"");
			if (!strcmp(name, line)) {
				snprintf(buf, len, eq);
				return 0;
			}
		}
	}
	fprintf(stderr, "SWMS:fls_mibget: %s not found\n", name);
	return -1;
}

static int fls_setvar2(struct variable_s *v, const char *name, const char *value)
{
	char buf[64];
	int logmask, enabled;
	in_addr_t logger;

	if (!strcasecmp(name, "AP_Mode")) {
		value = (!strcasecmp(value, "off")) ? "1" : "0";
		fls_mibget("WLAN1_WLAN_DISABLED", buf, sizeof(buf));
		if (strcmp(buf, value)) {
			//if (!yexecl(NULL, "flash set wlan0 WLAN_DISABLED %s", value))
			if (!nvram_set("WLAN1_WLAN_DISABLED", value)) {
				nvram_commit();
				return 0;
			}
		}
	} else if (!strcasecmp(name, "AP_Mode_5g")) {
		value = (!strcasecmp(value, "off")) ? "1" : "0";
		fls_mibget("WLAN0_WLAN_DISABLED", buf, sizeof(buf));
		if (strcmp(buf, value)) {
			//if (!yexecl(NULL, "flash set wlan0 WLAN_DISABLED %s", value))
			if (!nvram_set("WLAN0_WLAN_DISABLED", value)) {
				nvram_commit();
				return 0;
			}
		}
	} else if (!strcasecmp(name, "IGMP")) {
		value = (!strcasecmp(value, "0")) ? "1" : "0";
		return fls_setvar(v, name, value);
	} else if (!strcasecmp(name, "Syslog_Server")) {
		struct sockaddr_in addr_inet;

		if (value == NULL || !inet_aton(value, &addr_inet.sin_addr))
			return -1;

		logger = inet_addr(value);
		fls_mibget("SCRLOG_ENABLED", buf, sizeof(buf));
		logmask = atoi(buf);
		fls_mibget("REMOTELOG_ENABLED", buf, sizeof(buf));
		enabled = atoi(buf);
		fls_mibget("REMOTELOG_SERVER", buf, sizeof(buf));
		if (logger == 0 || logger == (in_addr_t) - 1) {
			// Disable remote syslog
			if (!enabled)
				return -1;
			//yexecl(NULL, "flash set REMOTELOG_ENABLED 0");
			nvram_set("REMOTELOG_ENABLED", "0");
			nvram_commit();
		} else {
			// Enable remote syslog
			if ((logmask & 1) && enabled && logger == inet_addr(buf))
				return -1;
			if (!(logmask & 1))
				//yexecl(NULL, "flash set SCRLOG_ENABLED %d", (logmask | 1));
				sprintf(buf, "%d", (logmask | 1));
			nvram_set("SCRLOG_ENABLED", buf);
			if (!enabled)
				//yexecl(NULL, "flash set REMOTELOG_ENABLED 1");
				nvram_set("REMOTELOG_ENABLED", "1");
			if (logger != inet_addr(buf))
				//yexecl(NULL, "flash set REMOTELOG_SERVER %s", value);
				nvram_set("REMOTELOG_SERVER", value);

			nvram_commit();
		}
		return 0;
	}
	return -1;
}

#define VERSION_LINE	3
static int dv_variable(struct variable_s *v, const char *name, const char *value)
{
	char buf[80];
	char str_date[32];
	char str_time[32];

	if (!strcasecmp(name, "ekqh_release_time")) {
		if (value[0] != 0) {
			yfcat("/etc/version", "%*s %*s %*s %s", str_date);
			yfcat("/etc/version", "%*s %*s %*s %*s %s", str_time);

			ydespaces(str_date);
			ydespaces(str_time);
			sprintf(buf, "%s %s", str_date, str_time);

			ydespaces(value);
			if (strcmp(value, buf))
				dv_force_upgrade = 1;
		}
	} else if (!strcasecmp(name, "ekqhfldzm_rev")) {
		if (value[0] != 0) {
			yfcat("/etc/version", "%*s %*s %s", buf);
			if (!strcmp(buf, value))	// same revision
				return -1;

			led_flag = 1;
			dv_force_upgrade = 1;
		}
	}
	return 0;
}

static int nvram_setvar(struct variable_s *v, const char *name, const char *value)
{
	char *nv_name = (char *)v->data;
	char *nv_val;

	if (nv_name) {
		//nv_val = dvnv_get_def(nv_name, "");
		nv_val = nvram_safe_get(nv_name);
		ystrtrim(nv_val, " \t\r\n\"");
		if (strcmp(nv_val, (char *)value)) {
			//dvnv_set(nv_name, (char *)value);
			nvram_set(nv_name, (char *)value);
			nvram_commit();
			return 0;
		}
	}
	return -1;
}

static int fwinfo_setvar(struct variable_s *v, const char *name, const char *value)
{
	int mj, mi, cf;

	if (!strcasecmp(v->name, "Firmware_File"))
		snprintf(fw_info.binname, sizeof(fw_info.binname), "%s", value);
	else if (!strcasecmp(v->name, "Firmware_Server"))
		snprintf(fw_info.binpath, sizeof(fw_info.binpath), "%s", value);
	else if (!strcasecmp(v->name, "Firmware_Version")) {
		if (sscanf(value, "%d.%d.%d", &mj, &mi, &cf) == 3) {
			fw_info.new.i.major = mj;
			fw_info.new.i.minor = mi;
			fw_info.new.i.conf = cf;
		} else
			return -1;
	}
	return 0;
}

static int fls_setvar(struct variable_s *v, const char *name, const char *value)
{
	char *fls_name = (char *)v->data;
	char fls_val[128];

	if (fls_name && !fls_mibget(fls_name, fls_val, sizeof(fls_val))) {
		if (strcmp(fls_val, value)) {
			//if (!yexecl(NULL, "flash set %s \"%s\"", fls_name, value))
			if (!nvram_set(fls_name, value)) {
				nvram_commit();
				return 0;
			}
		}
	}
	return -1;
}

#if !NETCFG_DISABLE
static int ippool_preset(struct variable_s *v, const char *name, const char *value)
{
	struct in_addr *p = (struct in_addr *)v->data;
	if (p)
		inet_aton(value, p);
	return -1;
}

static int ippool_postset(void)
{
	char buf[64];
	struct in_addr ip, netmask, subnet, tmp1, tmp2;
	int res = -1;

	if (!ippool[0].s_addr || !ippool[1].s_addr || (ippool[0].s_addr > ippool[1].s_addr))
		return -1;

	fls_mibget("DHCP_CLIENT_START", buf, sizeof(buf));
	if (!inet_aton(buf, &tmp1))
		return -1;

	fls_mibget("DHCP_CLIENT_END", buf, sizeof(buf));
	if (!inet_aton(buf, &tmp2))
		return -1;

	if (ippool[0].s_addr == tmp1.s_addr && ippool[1].s_addr == tmp2.s_addr)
		return -1;

	fls_mibget("IP_ADDR", buf, sizeof(buf));
	if (!inet_aton(buf, &ip))
		return -1;

	fls_mibget("SUBNET_MASK", buf, sizeof(buf));
	if (!inet_aton(buf, &netmask))
		return -1;

	if (!ip.s_addr || ip.s_addr == (in_addr_t) - 1 || !netmask.s_addr || netmask.s_addr == (in_addr_t) - 1)
		return -1;

	subnet.s_addr = ip.s_addr & netmask.s_addr;
	if (((ippool[0].s_addr & netmask.s_addr) != subnet.s_addr) ||
	    ((ippool[1].s_addr & netmask.s_addr) != subnet.s_addr) ||
	    (ippool[0].s_addr == subnet.s_addr) ||
	    (ippool[0].s_addr == (subnet.s_addr | ~netmask.s_addr)) || (ippool[1].s_addr == (subnet.s_addr | ~netmask.s_addr)))
		return -1;

	if (ippool[0].s_addr <= ip.s_addr && ippool[1].s_addr >= ip.s_addr)
		return -1;

	/*
	if (!yexecl(NULL, "flash set DHCP_CLIENT_START %s", inet_ntoa(ippool[0])))
		res = 0;
	if (!yexecl(NULL, "flash set DHCP_CLIENT_END %s", inet_ntoa(ippool[1])))
		res = 0;
	*/
	if (!nvram_set("DHCP_CLIENT_START", inet_ntoa(ippool[0]))) {
		nvram_commit();
		res = 0;
	}
	if (!nvram_set("DHCP_CLIENT_END %s", inet_ntoa(ippool[1]))) {
		nvram_commit();
		res = 0;
	}

	return res;
}
#endif

static int validate_type(const char *val, int type)
{
	int res;
	struct in_addr ip;

	if (!val)
		return 0;

	switch (type & TYPE_MASK) {
	case TYPE_STRING:
		return 0;
	case TYPE_INT:
		return strtoi(val, &res);
	case TYPE_IPV4:
		if (inet_aton(val, &ip) != 0)
			return 0;
		break;
	case TYPE_PORT:
		if (!strtoi(val, &res) && res > 0 && res <= 0x10000)
			return 0;
		break;
	case TYPE_ONOFF:
		if (!strcasecmp(val, "on") || !strcasecmp(val, "off"))
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
		nvram_get_r_def(q, value, sizeof(value), (!strncasecmp(q, "WLAN", 4)) ? "wlan0" : NULL);
		n = snprintf(buffer, len, "%s=%s\n", q, value);
		if (n >= len)
			break;
		len -= n;
		buffer += n;
	}
	free(plist);
	*buffer = '\0';

	return 0;
}

static int parse_config(struct fwinfo *info, char *fmem, int *flgs)
{
	char buf[128];
	variable *v;
	char *value, *name;
	struct in_addr ip;

	info->binpath[0] = '\0';
	info->binname[0] = '\0';
	info->new.all = 0;
	memset(ippool, 0, sizeof(ippool));
	flash_mib_mget(flsbuffer, sizeof(flsbuffer));

	while ((fmem = read_line(fmem, buf, sizeof(buf)))) {
		value = buf;
		name = strsep(&value, "=");
		if (!name)
			continue;
		ystrtrim(name, " \t\r\n\"");
		/* Comment */
		if (name[0] == '#')
			continue;
		if (value)
			ystrtrim(value, " \t\r\n\"");
		else
			value = "";

		for (v = &vartbl[0]; v->name; v++) {
			if (!strcasecmp(v->name, name)) {
				/* do a set of sanity check */
				if ((v->flgs & FLG_NILNOK) && !value[0])
					break;
				if ((v->flgs & FLG_INANY) && !value[0])
					value = "0.0.0.0";
				if (validate_type(value, v->flgs))
					break;
				if ((v->flgs & FLG_INETATON)) {
					inet_aton(value, &ip);
					if (ip.s_addr == 0 || ip.s_addr == (in_addr_t) - 1)
						break;
				}
				if (verbose >= L_DBG)
					fprintf(stderr, "SWMS: %s=%s\n", name, value);
				if (!v->setvar(v, name, value)) {
					if ((v->flgs & FLG_REBOOT) && flgs)
						*flgs = 1;
				}
				break;
			}
		}
	}

#if !NETCFG_DISABLE
	if (!ippool_postset() && flgs)
		*flgs = 1;
#endif

	return 0;
}

static int initenv(struct fwinfo *info)
{
	char dir[128], tmp[128], cfg[128], serial[128];
	char f_serv[128], f_name[128], f_tmp[128], prefix[128];
	int mj, mi, cf;
	char *saveptr, *pre;
	char vers[32];

	dv_force_upgrade = 0;
	led_flag = 0;
	memset(info, 0, sizeof(*info));
	f_tmp[0] = 0;

	yfcat("/etc/version", "%*s %s", vers);
	if (sscanf(vers, "%d.%d.%d", &mj, &mi, &cf) == 3) {
		info->cur.i.major = mj;
		info->cur.i.minor = mi;
		info->cur.i.conf = cf;
		sprintf(f_tmp, SYS_NAME "_%d.%d.%d.img", mj, mi, cf);

	}

	if (safe_atoi(nvram_safe_get("x_autoup_enabled"), 1)) {
		nvram_get_r_def("x_autoup_domain", dir, sizeof(dir), SKBB_DEF_URL);
#if defined(CONFIG_OEM_SKT)
		nvram_get_r_def("x_autoup_file", cfg, sizeof(cfg), SKT_DEF_CFG);
#else
		nvram_get_r_def("x_autoup_file", cfg, sizeof(cfg), SKBB_DEF_CFG);
#endif
		nvram_get_r_def("x_autoup_firm_server", f_serv, sizeof(f_serv), SKBB_DEF_FIRM_URL);
		nvram_get_r_def("x_autoup_prefix", prefix, sizeof(prefix), SKBB_DEF_PREFIX);
		nvram_get_r_def("x_autoup_firm_name", f_name, sizeof(f_name), f_tmp);

		/* For legacy 800 devices */
		if (!strcmp(dir, "iptvsh-mgnt.skbroadband.com") &&
		    strlen(dir) == strlen("iptvsh-mgnt.skbroadband.com"))
			strcpy(dir, "iptvsh-mgnt.skbroadband.com:12380");

		/* For empty serial number */
		nvram_get_r_def("HW_NIC1_ADDR", tmp, sizeof(tmp), NULL);

		/* init firmware info - snmp */
		snprintf(info->binpath, sizeof(fw_info.binpath), "%s", f_serv);

		pre = strtok_r(&prefix[0], "/ \t\r\n", &saveptr);
		snprintf(info->binname, sizeof(fw_info.binname), "/%s/%s", pre, f_name);

		/* Build URL */
		sprintf(info->confurl, "http://%s/config?mac=%s&id=DD-EF-33-11&cfg=%s", dir, tmp, cfg);
	}

	info->background = safe_atoi(nvram_safe_get("x_autoup_forever"), 0);
	return (info->confurl[0] && info->cur.all) ? 0 : -1;
}

static int do_wget(struct fwstat *fbuf, int *exp, int timeo, const char *url)
{
	char cmd[256];
	int try;
	long ts, waiths;

	snprintf(cmd, sizeof(cmd) - 13, "wget -q -O - \"%s\"%s",
		 url, (fw_info.quiet) ? " 2>/dev/null" : "");
#if 0
	fprintf(stderr, "SWMS: %s\n", cmd);
#endif
	for (try = 0; try < MAX_TRY; try++) {
		//if (tries == 2)
		//    uds_printf("/var/swms.uds", "kick-off taps");

		ts = times(NULL);
		/* put the 5 mins cap */
		if (*exp < 7)
			waiths = ((3 * (1 << *exp)) + (rand() % 3) + 1) * 100;
		else
			waiths = (300 + (rand() % 3) + 1) * 100;
		++*exp;

		if (!furl(cmd, timeo, (p_read_f) fw_read_callback, (void *)fbuf)) {
			return (!fbuf->lasterror && fbuf->rcvlen > 0) ? 0 : -1;
		}

		waiths -= (times(NULL) - ts);
		if (waiths <= 0)
			waiths = 1;
		usleep(waiths * 10000);
	}

	return -1;
}

static inline int newer_version(version_t * new, version_t * cur)
{
	return ((new->all == cur->all) ||
		(new->i.major < cur->i.major) ||
		((new->i.major == cur->i.major) && (new->i.minor < cur->i.minor)) ||
		((new->i.major == cur->i.major) && (new->i.minor == cur->i.minor) && (new->i.conf < cur->i.conf))) ? 0 : 1;
}

static void sig_term(int signo)
{
	//uds_printf("/var/swms.uds", "Exited!");
	_exit(-1);
}

int main(void)
{
	struct fwstat fbuf;
	char buffer[2048];
	int exp, status;
	int do_reboot;
	time_t t;
	version_t realver;

	verbose = safe_atoi(nvram_safe_get("x_user_loglevel"), L_ERR);

	signal(SIGTERM, sig_term);

	if (initenv(&fw_info)) {
		fprintf(stderr, "SWMS: Environment's Insufficient\n");
		sig_term(0);
	}

	do {
		status = 0;
		memset(&fbuf, 0, sizeof(fbuf));
		fbuf.fmem = buffer;
		fbuf.caplen = 1024;
		if (!do_wget(&fbuf, &tries, MAX_TIMEO, fw_info.confurl)) {
			fbuf.fmem[fbuf.rcvlen] = '\0';
			do_reboot = 0;
			if (!parse_config(&fw_info, fbuf.fmem, &do_reboot)) {
				fprintf(stderr, "SWMS: parse_config needs %s\n", (do_reboot) ? "REBOOT" : "NO reboot");
				if ((fw_info.new.all && newer_version(&fw_info.new, &fw_info.cur)) || dv_force_upgrade) {
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
							fprintf(stderr, "SWMS: image length %d\n", fbuf.rcvlen);
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
							    (dv_force_upgrade || newer_version(&realver, &fw_info.cur)) &&
							    !(status = fw_dualize(&fbuf))) {
								//vfecho("/proc/gpio", "4 %d", (fbuf.rcvlen / 43840) + 80 + 24);
								//system ("echo o > /proc/gpio"); //led blinking
								if (led_flag)
									yecho("/proc/gpio", "b\n");
								ifconfig("br0", 0, NULL, NULL);
								status = fw_write(&fbuf, NULL, NULL);
								//status = fw_write(fbuf, FirmwarePreWrite, NULL);
								if (!status) {
									munmap(mm, MAX_FWSIZE);
									mm = MAP_FAILED;
									syslog(LOG_INFO, "SWMS\xec\x97\x90\xec\x84\x9c \xed\x8e\x8c\xec\x9b\xa8\xec\x96\xb4 "
									       "\xec\x97\x85\xea\xb7\xb8\xeb\xa0\x88\xec\x9d\xb4\xeb\x93\x9c "
									       "\xec\x99\x84\xeb\xa3\x8c\xeb\x90\xa8 [%d.%d.%d vers  %d bytes]",
									       fw_info.new.i.major, fw_info.new.i.minor, fw_info.new.i.conf, fbuf.rcvlen);
									t = time(NULL);
									strftime(buffer, sizeof(buffer), "%F %H:%M:%S", localtime(&t));
									nvram_set("swms_upgrade_time", buffer);
									nvram_commit();
									sys_reboot();
								} else
									ifconfig("br0", IFUP, NULL, NULL);
								if (led_flag)
									yecho("/proc/gpio", "B\n");
								//system ("echo x > /proc/gpio"); //led normal
							}
						} else
							status = -EGETFW;
					} while (exp < MAX_TRY && (status != -ESAMEVERS && status != -EIDENTITY));

					if (mm != MAP_FAILED)
						munmap(mm, MAX_FWSIZE);
					dv_force_upgrade = 0;
					led_flag = 0;
				} else
					status = -ESAMEVERS;
				if (do_reboot)
					sys_reboot();
			} else
				status = -EINVALCONF;
		} else
			status = -EGETCONF;

		//uds_printf("/var/swms.uds", fw_strerror(status));
		fprintf(stderr, "SWMS: %s\n", fw_strerror(status));

		fw_info.quiet = 1;
	} while (fw_info.background);

	return 0;
}
