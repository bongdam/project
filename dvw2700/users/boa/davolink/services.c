#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <libytool.h>
#ifdef CONFIG_NVRAM_APMIB
#include "nvram_mib/nvram_mib.h"
#endif
#include "apmib.h"
#include "mibtbl.h"
#include "custom.h"
#include "md5.h"
#include "sha256.h"

static int normalize_cmdline(void *buf, size_t len, const char *fmt, ...)
{
	va_list ap;
	char *path;
	int fd;
	char *p1, *p2;
	ssize_t ret = -1;

	va_start(ap, fmt);
	path = yvasprintf(buf, len, fmt, ap);
	va_end(ap);
	if (path != NULL) {
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			ret = read(fd, buf, len - 1);
			close(fd);
		}
		((char *)buf)[ret > 0 ? ret : 0] = '\0';

		for (p1 = p2 = buf; p1[0] || p1[1]; p1++) {
			if (*p1 != '\0')
				*p2++ = *p1;
			else
				*p2++ = ' ';
		}
		*p2 = '\0';

		if (path != buf)
			free(path);
	}
	return ret;
}

/*
  if comm has been run with different arguments, kill comm and run again.
 */
int test_and_run(const char *comm, char *cmdline, int sig)
{
	char buf[128];
	pid_t self, *p;
	size_t i, num_pid = getpidbyname(comm, &p);
	int matched = 0;

	if (num_pid > 0) {
		self = getpid();
		for (i = 0; i < num_pid; i++) {
			if (self == p[i])
				continue;
			if (cmdline[0] != '\0') {
				if (normalize_cmdline(buf, sizeof(buf),
				                      "/proc/%d/cmdline", p[i]) > 0 &&
				    !strcmp(buf, cmdline)) {
					errno = EEXIST;
					matched++;
					continue;
				}
			}
			kill(p[i], sig);
		}
		free(p);
	}

	if (!matched && cmdline[0] != '\0')
		return yexecl(NULL, "%s", cmdline);

	return -1;
}

int set_log(void)
{
	int remote_enabled, enabled = 0;
	struct in_addr ip;
	char remote_server[32], *hostname = NULL;
	char cmd[128] = {[0] = '\0' };
	char cmd2[24] = {[0] = '\0' };
	char buffer[128]  = { [0] = '\0' };

	apmib_get(MIB_SCRLOG_ENABLED, (void *)&enabled);
	if (enabled & 1) {
		remote_enabled = 0;
		remote_server[0] = '\0';
		apmib_get(MIB_REMOTELOG_ENABLED, (void *)&remote_enabled);
		if (remote_enabled) {
			apmib_get(MIB_REMOTELOG_SERVER, (void *)&ip);
			if (ip.s_addr && ip.s_addr != INADDR_NONE)
				strcpy(remote_server, inet_ntoa(ip));
		}

		snprintf(cmd, sizeof(cmd), "syslogd -S -L -l 7 -s 16 %s %s",
		         (remote_server[0]) ? "-R" : "", remote_server);
		strcpy(cmd2, "klogd -p +");
		hostname = nvram_get("HW_NIC0_ADDR");
		if (hostname) {
			gethostname(buffer, sizeof(buffer));
			sethostname(hostname, strlen(hostname));
		}
	}

	test_and_run("syslogd", ydespaces(cmd), SIGKILL);
	test_and_run("klogd", ydespaces(cmd2), SIGKILL);
	if (buffer[0])
		sethostname(buffer, strlen(buffer));
	return 0;
}

int start_telnetd(void)
{
	unsigned int tmout;

	if (nvram_atoi("telnet_enable", 0) == 1) {
		tmout = (unsigned int)nvram_atoi("telnet_tout", 300);
		yfecho("/var/telnetd.conf", O_WRONLY | O_CREAT | O_TRUNC, 0644, "telnet_tout %u\n", tmout);
		return yexecl(NULL, "sh -c \"telnetd &\"");
	}
	return killall(SIGKILL, "telnetd") ? 0 : -1;
}

int start_snmp(void)
{
	if (nvram_atoi("snmp_enable", 1) == 1)
		return yexecl(NULL, "sh -c \"snmp -a s&\"");
	return killall(SIGKILL, "snmp") ? 0 : -1;
}

#ifdef __CONFIG_APP_LABORER__
int start_gateway_keepalive(const char *intf, const char *alternative)
{
	struct in_addr serverid;
	char buf[64] = { [0] = '\0' };
	int n = 0;

	if (!nvram_atoi("dhcpc_watching_probe", 0))
		return -1;

	if (sdmz_configured(NULL, 0))
		n += snprintf(buf + n, sizeof(buf) - n, " -s %s", VAR_WAN_IP_FILE);
	if (alternative && (serverid.s_addr = inet_addr(alternative)) && serverid.s_addr != -1U)
		n += snprintf(buf + n, sizeof(buf) - n, " -d %s", inet_ntoa(serverid));

	return yexecl(NULL, "preq gwka -- -I %s -i %d -w %d -S /bin/relinit %s",
	              intf,
	              nvram_atoi("dhcpc_watching_time", 60),
	              nvram_atoi("dhcpc_watching_tout", 2),
	              buf);
}

int start_dad(int opmode)
{
	char buf[32] = { [0] = '\0' };

	if (nvram_atoi("ARPROBE_DISABLED", 0) == 1)
		return -1;
	if (sdmz_configured(NULL, 0))
		snprintf(buf, sizeof(buf), "-s %s", VAR_WAN_IP_FILE);
	return yexecl(NULL, "preq garp -- -I %s -S /bin/dadresolv %s",
		      (opmode == GATEWAY_MODE) ? "eth1" : "br0", buf);
}
#endif	/* __CONFIG_APP_LABORER__ */

#if 0
/* APACRTL-524 */
static void fill_wl_restrict_list(void)
{
	int i, j, cnt;
	FILE *fp = NULL;
	char name[28], val[40];

	for (i = 0; i < 2; i++) {
		if (i == 0)
			fp = fopen("/tmp/.wl_restrict_list_5g", "w");
		else
			fp = fopen("/tmp/.wl_restrict_list_2g", "w");

		if (fp) {
			snprintf(name, sizeof(name), "WLAN%d_MACAC_ENABLED", i);
			nvram_get_r_def(name, val, sizeof(val), "0");
			if (atoi(val) > 0) {
				snprintf(name, sizeof(name), "WLAN%d_MACAC_NUM", i);
				nvram_get_r_def(name, val, sizeof(val), "0");
				cnt = atoi(val);

				for (j = 1; j <= cnt; j++) {
					snprintf(name, sizeof(name), "WLAN%d_MACAC_ADDR%d", i, j);
					nvram_get_r(name, val, sizeof(val));
					fprintf(fp, "%s\n", val);
				}
			}

			fclose(fp);
		}
	}
}

static void fill_child_guard_list(int num)
{
	int i;
	FILE *fp = NULL;
	char name[24], tmp[80];

	if ((fp = fopen("/tmp/.child_guard_list", "w"))) {
		for (i = 1; i <= num; i++) {
			snprintf(name, sizeof(name), "sta_protection_list%d", i);
			nvram_get_r(name, tmp, sizeof(tmp));

			fprintf(fp, "%s\n", tmp);
		}
		fclose(fp);
	}
}

int start_childguard(void)
{
	int num;

	num = nvram_atoi("sta_protection_num", 0);

	if (num > 0) {
		fill_child_guard_list(num);
		fill_wl_restrict_list();
		return yexecl(NULL, "sh -c \"child_guard &\"");
	}
	return killall(SIGKILL, "child_guard") ? 0 : -1;
}

int start_holepunch(void)
{
	if (nvram_atoi("x_holepunch_enabled", 1) == 1)
		return yexecl(NULL, "sh -c \"holepunch &\"");
	return killall(SIGKILL, "holepunch") ? 0 : -1;
}

int start_autoreboot(void)
{
	FILE *f;
	char tmp[32];

	if (nvram_atoi("x_auto_reboot_enable", 0) != 1)
		return killall(SIGKILL, "auto_reboot") ? 0 : -1;
	f = fopen("/var/config/auto_reboot", "w");
	if (f == NULL) {
		perror("/var/config/auto_reboot");
		return -1;
	}
	fprintf(f, "autoreboot_userforce=%d\n", nvram_atoi("x_autoreboot_userforce", 0));
	fprintf(f, "auto_reboot_enable=%d\n", nvram_atoi("x_auto_reboot_enable", 1));
	fprintf(f, "auto_reboot_dbg=%d\n", nvram_atoi("x_auto_reboot_dbg", 0));
	fprintf(f, "auto_reboot_on_idle=%d\n", nvram_atoi("x_auto_reboot_on_idle", 1));
	fprintf(f, "auto_uptime=%s\n", _nvram_get_r("x_auto_uptime", tmp, sizeof(tmp), "7d"));
	fprintf(f, "auto_wan_port_idle=%d\n", nvram_atoi("x_auto_wan_port_idle", 1));
	fprintf(f, "auto_hour_range=%s\n", _nvram_get_r("x_auto_hour_range", tmp, sizeof(tmp), "04:30-05:00"));
	fprintf(f, "auto_check_day=%d\n", nvram_atoi("x_auto_check_day", 1));
	fprintf(f, "auto_bw_kbps=%d\n", nvram_atoi("x_auto_bw_kbps", 1000));
	fprintf(f, "auto_bw_mon_min=%d\n", nvram_atoi("x_auto_bw_mon_min", 1));
	fprintf(f, "auto_sleep_ps_min=%d\n", nvram_atoi("x_auto_sleep_ps_min", 15));
	fprintf(f, "auto_sleep_random_min=%d\n", nvram_atoi("x_auto_sleep_random_min", 20));
	fprintf(f, "autoreboot_week=%s\n", _nvram_get_r("x_autoreboot_week", tmp, sizeof(tmp), "5-5"));
	fprintf(f, "op_mode=%s\n", _nvram_get_r("OP_MODE", tmp, sizeof(tmp), "0"));
	fprintf(f, "autoreboot_wancrc=%d\n", nvram_atoi("x_autoreboot_wancrc", 20));
	fclose(f);

	return yexecl(NULL, "sh -c \"auto_reboot &\"");
}
#endif

void cal_sha256(char *plain_txt, char *sha256_txt)
{
	sha256_context ctx;
	unsigned char md[32];

	sha256_starts(&ctx);
	sha256_update(&ctx, (uint8 *) plain_txt, strlen(plain_txt));
	sha256_finish(&ctx, md);
	yitoxa(sha256_txt, md, 32);
}

/*
* base64 encoder
*
* encode 3 8-bit binary bytes as 4 '6-bit' characters
*/
char *b64_encode(unsigned char *src, int src_len, unsigned char *space, int space_len)
{
	static const char cb64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	unsigned char *out = space;
	unsigned char *in = src;
	int sub_len, len;
	int out_len;

	out_len = 0;

	if (src_len < 1)
		return NULL;
	if (!src)
		return NULL;
	if (!space)
		return NULL;
	if (space_len < 1)
		return NULL;

	/* Required space is 4/3 source length  plus one for NULL terminator */
	if (space_len < ((1 + src_len / 3) * 4 + 1))
		return NULL;

	memset(space, 0, space_len);

	for (len = 0; len < src_len; in = in + 3, len = len + 3) {

		sub_len = ((len + 3 < src_len) ? 3 : src_len - len);

		/* This is a little inefficient on space but covers ALL the
		   corner cases as far as length goes */
		switch (sub_len) {
		case 3:
			out[out_len++] = cb64[in[0] >> 2];
			out[out_len++] = cb64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
			out[out_len++] = cb64[((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)];
			out[out_len++] = cb64[in[2] & 0x3f];
			break;
		case 2:
			out[out_len++] = cb64[in[0] >> 2];
			out[out_len++] = cb64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
			out[out_len++] = cb64[((in[1] & 0x0f) << 2)];
			out[out_len++] = (unsigned char)'=';
			break;
		case 1:
			out[out_len++] = cb64[in[0] >> 2];
			out[out_len++] = cb64[((in[0] & 0x03) << 4)];
			out[out_len++] = (unsigned char)'=';
			out[out_len++] = (unsigned char)'=';
			break;
		default:
			break;
			/* do nothing */
		}
	}
	out[out_len] = '\0';
	return (char *)out;
}

/* Base-64 decoding.  This represents binary data as printable ASCII
** characters.  Three 8-bit binary bytes are turned into four 6-bit
** values, like so:
**
**   [11111111]  [22222222]  [33333333]
**
**   [111111] [112222] [222233] [333333]
**
** Then the 6-bit values are represented using the characters "A-Za-z0-9+/".
*/

static const char b64_decode_table[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* 00-0F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* 10-1F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,	/* 20-2F */
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,	/* 30-3F */
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,	/* 40-4F */
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,	/* 50-5F */
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,	/* 60-6F */
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,	/* 70-7F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* 80-8F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* 90-9F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* A0-AF */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* B0-BF */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* C0-CF */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* D0-DF */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* E0-EF */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1	/* F0-FF */
};

/* Do base-64 decoding on a string.  Ignore any non-base64 bytes.
** Return the actual number of bytes generated.  The decoded size will
** be at most 3/4 the size of the encoded, and may be smaller if there
** are padding characters (blanks, newlines).
*/
int b64_decode(const char *str, unsigned char *space, int size)
{
	const unsigned char *cp;
	int space_idx, phase;
	int d, prev_d = 0;
	unsigned char c;

	space_idx = 0;
	phase = 0;
	for (cp = (unsigned char *)str; *cp != '\0'; ++cp) {
		d = b64_decode_table[*cp];
		if (d != -1) {
			switch (phase) {
			case 0:
				++phase;
				break;
			case 1:
				c = ((prev_d << 2) | ((d & 0x30) >> 4));
				if (space_idx < size)
					space[space_idx++] = c;
				++phase;
				break;
			case 2:
				c = (((prev_d & 0xf) << 4) | ((d & 0x3c) >> 2));
				if (space_idx < size)
					space[space_idx++] = c;
				++phase;
				break;
			case 3:
				c = (((prev_d & 0x03) << 6) | d);
				if (space_idx < size)
					space[space_idx++] = c;
				phase = 0;
				break;
			}
			prev_d = d;
		}
	}
	return space_idx;
}

int set_jumbo_frm()
{
#if 0 /* APACRTL-25 */
	int isUse, frm_size, def_size = 9000;

	/* Always allow to accept 9k pkt. */
	yecho("/proc/jumbo_frame_support", "1 %d", def_size);

	isUse = nvram_atoi("x_jumbo_enable", 0);
	if (isUse == 0)
		frm_size = 1500;
	else
		frm_size = nvram_atoi("x_jumbo_size", 0);
	if (isUse == 1 && (frm_size == 0 || frm_size <= 1500)) {
		printf("ERROR: jumbo frame size error");
		return -1;
	}
	if (frm_size > def_size) {
		yecho("/proc/jumbo_frame_support", "%d %d", isUse, (isUse == 0) ? 0 : frm_size);
	}
	//yexecl(NULL, "ifconfig br0 mtu %d", frm_size);
	yexecl(NULL, "ifconfig eth0 mtu %d", frm_size);
	yexecl(NULL, "ifconfig eth1 mtu %d", frm_size);
#endif
	return 1;
}
#if 0
void set_lan_restrict(void)
{
	char name[64];
	int i;

	if (nvram_atoi("x_LANRESTRICT_ENABLE", 0)) {
		yecho("/proc/lan_restrict_info", "enable");
		for (i = 1; i <= 4; i++) {
			sprintf(name, "x_LANRESTRICT_ENABLE_PORT%d", i);
			if (nvram_atoi(name, 0) == 1) {
				sprintf(name, "x_LANRESTRICT_MAXNUM%d", i);
				yecho("/proc/lan_restrict_info", "%d on %d",
				      i, nvram_atoi(name, 4));
			} else
				yecho("/proc/lan_restrict_info", "%d off 0", i);
		}
	} else
		yecho("/proc/lan_restrict_info", "disable");
}

void start_provisioning(void)
{
	if (nvram_atoi("x_autoup_enabled", 1)) {
		if (access("/tmp/.swms_started", F_OK) != 0) {
			yexecl(NULL, "sh -c \"swms &\"");
			yecho("/tmp/.swms_started", "1\n");
		}
	} else if (nvram_atoi("x_ldap_enabled", 1)) {
		if (access("/tmp/.ldap_started", F_OK) != 0) {
			yexecl(NULL, "sh -c \"ldap &\"");
			yecho("/tmp/.ldap_started", "1\n");
		}
	}
}

void start_httpd(void)
{
	char opt[16];

	opt[0] = '\0';
	if (nvram_atoi("x_http_log_disabled", 0) == 1)
		strcat(opt, " -s");
	if (nvram_atoi("x_http_log_stderr", 0) == 1)
		strcat(opt, " -g");

	if (get_repeater_mode())	/* APACRTL-84  smlee 20151029 */
		yexecl(NULL, "boa %s -p 80", opt);
	else if (nvram_atoi("OP_MODE", 0) == 0)
		yexecl(NULL, "boa %s -p 80 -i %s", opt, nvram_safe_get("IP_ADDR"));
	else
		yexecl(NULL, "boa %s -p 8080 -i %s", opt, nvram_safe_get("IP_ADDR"));
}
#endif

#define MAX_ACL_ENTRY	37 //MAX 32 + DEFAULT 5

typedef struct {
	int num;
	struct inet_tuple {
		uint32_t addr, mask;	/* host-byte order */
	} addrs[MAX_ACL_ENTRY];
} inet_db_t;

static int inet_db_add(inet_db_t *N, uint32_t addr, uint32_t mask)
{
	struct inet_tuple *t;
	int i, res = 0;

	if (N->num < MAX_ACL_ENTRY) {
		for (i = 0; i < N->num; i++) {
			t = &N->addrs[i];
			if (!(((t->addr & mask) ^ (addr & mask)) &&
			      (t->addr ^ (addr & t->mask)))) {
				if (ntohl(mask) < ntohl(t->mask))
					t->mask = mask;
				t->addr = addr & t->mask;
				break;
			}
		}

		if (i >= N->num) {
			N->addrs[N->num].addr = (addr & mask);
			N->addrs[N->num].mask = mask;
			N->num++;
		}
	} else
		res = -1;

	return res;
}

static int inet_db_parse(inet_db_t *N, const char *s)
{
	char tmp[64];
	struct in_addr ip, mask;
	char *p, *end;
	int i, cmask;

	snprintf(tmp, sizeof(tmp), "%s", s);
	p = strchr(tmp, '/');
	if (p) {
		*p++ = '\0';
		ydespaces(p);
	} else
		p = "255.255.255.255";

	ydespaces(tmp);
	if (inet_pton(AF_INET, tmp, (void *)&ip) <= 0)
		return -1;

	if (inet_pton(AF_INET, p, (void *)&mask) <= 0) {
		cmask = strtol(p, &end, 10);
		if (*end || end == p || cmask < 0 || cmask > 32)
			return -1;
		mask.s_addr = (uint32_t) - 1;
		cmask = 32 - cmask;
		for (i = 0; cmask > 0; i++, cmask--)
			mask.s_addr ^= (1 << i);
		mask.s_addr = htonl(mask.s_addr);
	}

	return inet_db_add(N, ip.s_addr, mask.s_addr);
}

void acl_init_rule(char *iface, int opmode, int flt_fd, int nat_fd)
{
	(void)iface;
	(void)opmode;
	(void)nat_fd;
	dprintf(flt_fd, "-A ACL -j DROP\n");
}

static void put_acl_item(inet_db_t *N, int flt_fd, char *proto, int port)
{
	int i;
	for (i = 0; i < N->num; i++) {
		dprintf(flt_fd, "-I ACL --source %u.%u.%u.%u/%u.%u.%u.%u -p %s --dport %d -j ACCEPT\n",
		        NIPQUAD(N->addrs[i].addr), NIPQUAD(N->addrs[i].mask), proto, port);
	}
}

void put_acl_chain(int flt_fd, char *proto, int port)
{
	static int db_parse = 0;
	static inet_db_t N;
	if (db_parse == 0) {
		char *p = NULL;
		char cmd[64];
		int white_list_num = 0;
		int i;
		memset(&N, 0, sizeof(N));
		white_list_num = nvram_atoi("acl_white_list_num", 0);
		for (i = 1; i <= white_list_num; i++) {
			sprintf(cmd, "acl_white_list%d", i);
			p = nvram_get(cmd);
			if (p) {
				sprintf(cmd, "%s", p);
				inet_db_parse(&N, cmd);
			}
		}
		db_parse = 1;
	}
	put_acl_item(&N, flt_fd, proto, port);
}

void web_remote_access(char *iface, int opmode, int flt_fd, int nat_fd)
{
	int wwwAclPort = 0, wwwPort = 80;
	struct in_addr lan_ip, lan_mask;
	int acl_num = 0, web_acl = 0;
	int i;
	char cmd[64], buffer[64];
	struct in_addr nip;
	int all_flag = 0;
	char wan_nip[32], lan_nip[32], lan_nmask[32];
	int remote_access = 0;

	apmib_get(MIB_IP_ADDR, (void *)&lan_ip);
	apmib_get(MIB_SUBNET_MASK, (void *)&lan_mask);
	wwwAclPort = nvram_atoi("webacl_port", 8787);
	sprintf(lan_nip, "%u.%u.%u.%u", NIPQUAD(lan_ip.s_addr));
	sprintf(lan_nmask, "%u.%u.%u.%u", NIPQUAD(lan_mask.s_addr));

	remote_access = nvram_atoi("webman_enable", 0);

	if (remote_access == 0) {
		if (opmode == BRIDGE_MODE) {
			dprintf(flt_fd, "-A INPUT -p tcp ! --source %s/%s --dport %d -j DROP\n",
			        lan_nip, lan_nmask, wwwAclPort);
		}
		return;
	}

	memset(wan_nip, 0, sizeof(wan_nip));
	yfcat("/var/wan_ip", "%s", wan_nip);
	if (strnlen(wan_nip, 30) < 6) {
		return;
	}

	web_acl = nvram_atoi("webacl_mode", 0);
	if (web_acl) {
		acl_num = nvram_atoi("webacl_num", 0);
	} else {
		all_flag = 1;
	}

	dprintf(flt_fd, "-I ACL --source %s/%s -p tcp --dport %d -j ACCEPT\n", lan_nip, lan_nmask, wwwPort);

	if (opmode == GATEWAY_MODE) {
		dprintf(nat_fd, "-A PREROUTING -i %s -p tcp -d %s --dport %d -j DNAT --to %s:%d\n",
		        iface, wan_nip, wwwAclPort, lan_nip, wwwPort);
		dprintf(flt_fd, "-A INPUT -p tcp -d %s --dport %d -j ACL\n", lan_nip, wwwPort);
		wwwAclPort = wwwPort;
	} else {
		dprintf(flt_fd, "-A INPUT -p tcp --dport %d -j ACL\n", wwwAclPort);
	}

	if (web_acl) {
		if (acl_num) {
			for (i = 1; i <= acl_num; i++) {
				snprintf(cmd, sizeof(cmd), "webacl_addr%d", i);
				nvram_get_r_def(cmd, buffer, sizeof(buffer), "0.0.0.0");
				if (!strcmp(buffer, "0.0.0.0")) {
					all_flag = 1;
					break;
				}
				if (inet_aton(buffer, &nip) > 0 && (nip.s_addr > 0 && nip.s_addr < 0xffffffff)) {
					dprintf(flt_fd, "-I ACL --source %s -p tcp --dport %d -j ACCEPT\n", buffer, wwwAclPort);
				}
			}
		} else {
			all_flag = 1;
		}
	}
	if (all_flag) {
		dprintf(flt_fd, "-I ACL -p tcp --dport %d -j ACCEPT\n", wwwAclPort);
	} else {
		put_acl_chain(flt_fd, "tcp", wwwAclPort);
	}
}

void snmp_make_rules(char *iface, int opmode, int flt_fd, int nat_fd)
{
	int snmp_enable, n;
	unsigned short snmp_port;
	struct in_addr lan_ip;
	char wan_nip[32] = {0,}, lan_nip[32] = {0,};
	char name[32], white_list[60];
	char *args[2];

	snmp_enable = nvram_atoi("snmp_enable", 1);
	snmp_port = (unsigned short)nvram_atoi("snmp_port", 20161);
	apmib_get(MIB_IP_ADDR, (void *)&lan_ip);
	snprintf(lan_nip, sizeof(lan_nip), "%u.%u.%u.%u", NIPQUAD(lan_ip.s_addr));
	yfcat("/var/wan_ip", "%s", wan_nip);
	if (strnlen(wan_nip, 30) < 6) {
		return;
	}

	if (snmp_enable == 0) {
		return;
	}

	if (opmode == GATEWAY_MODE) {
		dprintf(nat_fd, "-A PREROUTING -i %s -p udp -d %s --dport %hd -j DNAT --to %s:%hd\n", iface, wan_nip, snmp_port, lan_nip, snmp_port);
		dprintf(flt_fd, "-A INPUT -i %s -p udp -d %s --dport %hd -j ACL\n", iface, lan_nip, snmp_port);
		//deny access by local
		dprintf(flt_fd, "-A INPUT -i br0 -p udp -d %s --dport %hd -j DROP\n", lan_nip, snmp_port);
	} else if (opmode == BRIDGE_MODE) {
		dprintf(flt_fd, "-A INPUT -p udp -d %s --dport %hd -j ACL\n", wan_nip, snmp_port);
	}

	//apms ip rule set
	snprintf(name, sizeof(name), "apms_ip");
	nvram_get_r_def(name, white_list, sizeof(white_list), "0.0.0.0");
	if (strcmp(white_list, "0.0.0.0")) {
		dprintf(flt_fd, "-I ACL --source %s -p udp --dport %hd -j ACCEPT\n", white_list, snmp_port);
	}

	//davo ip rule set
	snprintf(name, sizeof(name), "acl_white_list1");
	nvram_get_r_def(name, white_list, sizeof(white_list), "220.120.246.192/26");
	n = ystrargs(white_list, args, 2, " /\t\r\n", 0);
	if (n == 2) {
		dprintf(flt_fd, "-I ACL --source %s/%s -p udp --dport %hd -j ACCEPT\n", args[0], args[1], snmp_port);
	}
}

#define FIPQUAD(addr) \
    ((unsigned char *)&(addr)) + 0, \
    ((unsigned char *)&(addr)) + 1, \
    ((unsigned char *)&(addr)) + 2, \
    ((unsigned char *)&(addr)) + 3

static int get_free_port(in_addr_t ip, unsigned short port, int extent)
{
	struct sockaddr_in bsa;
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s != -1) {
		memset(&bsa, 0, sizeof(bsa));
		bsa.sin_addr.s_addr = ip;
		for (bsa.sin_family = AF_INET; extent-- >= 0; port++) {
			bsa.sin_port = htons(port);
			if (!bind(s, (struct sockaddr *)&bsa, sizeof(bsa)))
				return ({ close(s); port; });
		}
		close(s);
	}
	return -1;
}

static int stop_captive_service_failure(void)
{
	FILE *f;
	char buf[128], *p;
	struct in_addr ip;
	unsigned short port;

	f = fopen("/var/referer.html", "r");
	if (f == NULL)
		return -1;
	while (fgets(buf, sizeof(buf), f)) {
		if (!(p = strstr(buf, "http://")))
			continue;
		if (sscanf(p + sizeof("http://") - 1,
		           "%hhu.%hhu.%hhu.%hhu:%hu",
		           FIPQUAD(ip), &port) == 5)
			yexecl("2>/dev/null", "preq httpd -- -s %u.%u.%u.%u -p %d -q", NIPQUAD(ip), port);
	}
	fclose(f);
	return 0;
}

static int mkscript(const char *scr, const char *proto, u_int16_t port, int trap_sdmz_host)
{
	int fd;
	char buf[strlen(scr) + sizeof("/var/tmp/")], *p;

	p = basename(scr);
	snprintf(buf, sizeof(buf), "/var/tmp/%.*s", (int)(strchrnul(p, '.') - p), p);

	fd = open(scr, O_CREAT|O_WRONLY|O_TRUNC, 0755);
	if (fd < 0)
		return -1;

	dprintf(fd, "#!/bin/sh\n\n[ -f \"%s\" ] && { source %s; echo -n \"\" >%s; }\n", buf, buf, buf);
	dprintf(fd,
	        "[ ${1} -eq 1 ] && {\n"
	        "\tiptables -t nat -I PREROUTING -i br0 -p %s --dport %d ! -d ${2%%%%:*} -j DNAT --to ${2}\n"
	        "\techo \"iptables -t nat -D PREROUTING -i br0 -p %s --dport %d ! -d ${2%%%%:*} -j DNAT --to ${2}\" >%s\n",
	        proto, port, proto, port, buf);
	if (trap_sdmz_host)
		dprintf(fd,
		        "\tread -r gip < %s\n"
		        "\t[ -n \"${gip}\" -a \"${gip}\" != \"0.0.0.0\" ] && {\n"
		        "\t\taclwrite add br0 -d in -a cpu -r ip -i ${gip} -q -o 7\n"
		        "\t\techo \"aclwrite del br0 -d in -a cpu -r ip -i ${gip} -q -o 7\" >>%s\n"
		        "\t}\n", VAR_WAN_IP_FILE, buf);
	dprintf(fd, "}\n");
	close(fd);
	return 0;
}

int start_captive_service_failure(void)
{
	struct in_addr ip;
	int referer, referto;
	const char *scr53 = "/var/hijack53.sh";
	const char *scr80 = "/var/hijack80.sh";

	stop_captive_service_failure();

	if (nvram_atoi("DISABLE_CAPTIVE_SVCFAILURE", 0) == 1)
		return -1;

	apmib_get(MIB_IP_ADDR, (void *)&ip);
	referer = get_free_port(ip.s_addr, 7275, 10);
	if (referer < -1)
		return -1;
	referto = get_free_port(ip.s_addr, referer + 1, 10);
	if (referto < -1)
		return -1;

	mkscript(scr53, "udp", 53, 0);
	yexecl(NULL, "preq fdnsd -- -s %u.%u.%u.%u -f 10.10.253.254 -S %s", NIPQUAD(ip), scr53);
	yexecl(NULL, "preq httpd -- -s %u.%u.%u.%u -p %d -d /etc/oop/referto", NIPQUAD(ip), referto);
	mkscript(scr80, "tcp", 80, sdmz_configured(NULL, 0));
	yexecl(NULL, "preq httpd -- -s %u.%u.%u.%u -p %d -d /etc/oop/referer -o -S %s", NIPQUAD(ip), referer, scr80);

	yecho("/var/referer.html",
	      "<html>\n"
	      "  <head\n"
	      "    <title></title>\n"
	      "    <meta name=\"referer\" content=\"http://%u.%u.%u.%u:%d\" />\n"
	      "    <meta name=\"keywords\" content=\"Warning\" />\n"
	      "    <script></script>\n"
	      "  </head>\n"
	      "  <body>\n"
	      "    <meta http-equiv=\"refresh\" content=\"0; url='http://%u.%u.%u.%u:%d'\" />\n"
	      "  </body>\n"
	      "</html>\n",
	      NIPQUAD(ip), referer, NIPQUAD(ip), referto);

	return 0;
}
