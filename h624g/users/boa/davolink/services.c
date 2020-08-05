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
	char remote_server[64], *hostname = NULL;
	char cmd[128] = {[0] = '\0' };
	char cmd2[24] = {[0] = '\0' };
	char buffer[128]  ={ [0] = '\0' };

	apmib_get(MIB_SCRLOG_ENABLED, (void *)&enabled);
	if (enabled & 1) {
		remote_enabled = 0;
		remote_server[0] = '\0';
		apmib_get(MIB_REMOTELOG_ENABLED, (void *)&remote_enabled);
		if (remote_enabled) {
			nvram_get_r_def("x_remote_logserver", remote_server, sizeof(remote_server), "syslogap.skbroadband.com:10614");
			snprintf(cmd, sizeof(cmd), "syslogd -S -L -l 7 -s 16 -R %s", remote_server);
		} else
			snprintf(cmd, sizeof(cmd), "%s", "syslogd -S -L -l 7 -s 16");

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

int start_rtnetlnk(int opmode, int ntwk_mode)
{
	return yexecl(NULL, "sh -c \"rtnetlnk -i %s -a %d %s %s &\"",
		      (!opmode) ? ((ntwk_mode != 3) ? "eth1" : "ppp0") : "br0",
		      !!nvram_atoi("x_ipv6_autoconfig_method", 0),
		      sdmz_configured(NULL, 0) ? "-s" : "",
		      nvram_atoi("x_rtnetlnk_dbg", 0) ? "-v" : "");
}

int start_arprobe(int opmode, int ntwk_mode)
{
#if defined(CONFIG_IPV6)
	yexecl("2>/dev/null", "sh -c \"dadd -i br0 &\"");
#endif
	if (nvram_atoi("x_arprobe_disabled", 0) != 1)
		return yexecl(NULL, "arprobe -i %s %s %s %s %s",
			      (!opmode) ? ((ntwk_mode != 3) ? "eth1" : "ppp0") : "br0",
			      (sdmz_configured(NULL, 0)) ? "-s" : "",
			      nvram_atoi("x_arprobe_dbg", 0) ? "-v" : "",
			      (ntwk_mode == 1) ? "-b" : "",
/* APACRTL-94 */
				  ((nvram_atoi("REPEATER_ENABLED1", 0) || nvram_atoi("REPEATER_ENABLED2", 0)) ? "-r" : ""));

	return -1;
}

int start_telnetd(void)
{
	unsigned int tmout;

	if (nvram_atoi("x_telnet_enable", 0) == 1) {
		tmout = (unsigned int)nvram_atoi("x_telnet_tout", 300);
		yfecho("/var/telnetd.conf", O_WRONLY|O_CREAT|O_TRUNC, 0644, "telnet_tout %u\n", tmout);
		return yexecl(NULL, "sh -c \"telnetd &\"");
	}
	return killall(SIGKILL, "telnetd") ? 0 : -1;
}

int start_snmp(void)
{
	if (nvram_atoi("x_SNMP_ENABLE", 0) == 1)
		return yexecl(NULL, "sh -c \"snmp -a s&\"");
	return killall(SIGKILL, "snmp") ? 0 : -1;
}

/* APACRTL-524 */
static void fill_wl_restrict_list(void)
{
	int i, j, cnt;
	FILE *fp = NULL;
	char name[28], val[40];

	for (i=0; i<2; i++) {
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

				for (j=1; j<=cnt; j++) {
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
		for (i=1; i<=num; i++) {
			snprintf(name, sizeof(name), "sta_protection_list%d", i);
			nvram_get_r(name, tmp, sizeof(tmp));

			fprintf(fp, "%s\n", tmp);
		}
		fclose(fp);
	}
}

int start_childguard(void)
{
	int num, port;
	int op_mode = 0;
	int pid = 0;

	yfcat("/var/sys_op", "%d", &op_mode);

	if (op_mode != 0)
		return 0;

	num = nvram_atoi("sta_protection_num", 0);
	port = nvram_atoi("x_redirect_port", 876);

	yfcat("/var/run/child_guard.pid", "%d", &pid);
	if (pid > 0) {
		killall(SIGKILL, "restricted_web");
		killall(SIGKILL, "child_guard");
		usleep(50000);
	}

	if (num > 0)
		yexecl(NULL, "sh -c \"restricted_web -p %d&\"", port);

	return yexecl(NULL, "sh -c \"child_guard &\"");
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

void shift_str(char *src, char *dst, int tmp)
{
	int i;

	for (i=0; i<strlen(src); i++) {
		dst[i]=src[i]+tmp;
	}
	dst[strlen(src)]='\0';
	return;
}

/*void cal_md5(char *plain_txt, char *md5_txt)
{

	MD5_CONTEXT md5ctx;
	//char tmpBuf[200], hashBuf[33];
	char tmpBuf[200];
	unsigned char hash[16];
	int i;
	const char *hex = "0123456789abcdef";
	char *r;

	MD5Init(&md5ctx);
	MD5Update(&md5ctx, plain_txt, (unsigned int)strlen(plain_txt));
	MD5Final(hash, &md5ctx);
*/
	/*
	 *  Prepare the resulting hash string
	*/

/*	for (i = 0, r = md5_txt; i < 16; i++) {
		*r++ = toupper(hex[hash[i] >> 4]);
		*r++ = toupper(hex[hash[i] & 0xF]);
	}
	*r = '\0';
}*/
void cal_sha256(char *plain_txt, char *sha256_txt)
{
	sha256_context ctx;
	unsigned char sha256sum[32];
	int j;

	sha256_starts( &ctx );
	sha256_update( &ctx, (uint8 *) plain_txt, strlen( plain_txt ) );
	sha256_finish( &ctx, sha256sum );
	for( j = 0; j < 32; j++ )
	{
		sprintf( sha256_txt + j * 2, "%02x", sha256sum[j] );
	}

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
	return out;
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

static int b64_decode_table[256] = {
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
	const char *cp;
	int space_idx, phase;
	int d, prev_d = 0;
	unsigned char c;

	space_idx = 0;
	phase = 0;
	for (cp = str; *cp != '\0'; ++cp) {
		d = b64_decode_table[(int)*cp];
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

int start_fdns(void)
{
	int val = 0;

	yfcat("/var/sys_op", "%d", &val);

	if (val != 0)
		return 0;

	if (nvram_atoi("x_fdns_enabled", 1) == 1)
		return yexecl(NULL, "sh -c \"fdns &\"");
	return killall(SIGKILL, "fdns") ? 0 : -1;
}
