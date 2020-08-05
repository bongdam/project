#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/route.h>
#include <linux/wireless.h>
#include <signal.h>
#include "apmib.h"
#include "custom.h"

#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))

int strtoi(const char *s, int *ret)
{
	char *q;
	int saved_errno;

	if (!s || !s[0])
		return -1;
	saved_errno = errno;
	errno = 0;
	*ret = strtol(s, &q, 0);
	if (errno)
		return -1;
	if (s == q || !q || (*q && !isspace(*q))) {
		errno = EINVAL;
		return -1;
	}
	errno = saved_errno;
	return 0;
}

int safe_atoi(const char *s, int ndefault)
{
	int n;
	if (strtoi(s, &n))
		n = ndefault;
	return n;
}

int nvram_atoi(char *name, int dfl)
{
	char *p = nvram_get(name);
	return (p) ? (int)strtol(p, NULL, 0) : dfl;
}

char *init_abuffer(struct abuffer *m, size_t len)
{
	m->size = len;
	m->count = 0;
	return (m->buf = calloc(m->size, 1));
}

void fini_abuffer(struct abuffer *m)
{
	if (m && m->buf)
		free(m->buf);
}

int aprintf(struct abuffer *m, const char *f, ...)
{
	va_list args;
	size_t len;

	if (m == NULL || m->buf == NULL)
		return -1;

	while (m->count < m->size) {
		va_start(args, f);
		len = (size_t)vsnprintf(m->buf + m->count, m->size - m->count,
					f, args);
		va_end(args);
		if (len < (m->size - m->count)) {
			m->count += len;
			return 0;
		} else {
			char *p = realloc(m->buf, len + m->count + 1);
			if (!p)
				break;
			m->buf = p;
			m->size = len + m->count + 1;
		}
	}
	m->count = m->size;
	return -1;
}

#ifdef CONFIG_NVRAM_APMIB
#define TZ_FILE "/var/TZ"

void set_timeZone(void)
{
	unsigned int daylight_save = 1;
	//char daylight_save_str[5];
	char time_zone[8];
	char str_datnight[100];
	char str_tz1[32];

	apmib_get(MIB_DAYLIGHT_SAVE, (void *)&daylight_save);
	//memset(daylight_save_str, 0x00, sizeof(daylight_save_str));
	//sprintf(daylight_save_str, "%u", daylight_save);
	apmib_get(MIB_NTP_TIMEZONE, (void *)&time_zone);

	if (daylight_save == 0)
		str_datnight[0] = '\0';
	else if (strcmp(time_zone, "9 1") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "8 1") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "7 2") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "6 1") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "6 2") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "5 2") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "5 3") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/02:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "4 3") == 0)
		strcpy(str_datnight, "PDT,M10.2.0/00:00:00,M3.2.0/00:00:00");
	else if (strcmp(time_zone, "3 1") == 0)
		strcpy(str_datnight, "PDT,M4.1.0/00:00:00,M10.5.0/00:00:00");
	else if (strcmp(time_zone, "3 2") == 0)
		strcpy(str_datnight, "PDT,M2.2.0/00:00:00,M10.2.0/00:00:00");
	else if (strcmp(time_zone, "1 1") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/00:00:00,M10.5.0/01:00:00");
	else if (strcmp(time_zone, "0 2") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/01:00:00,M10.5.0/02:00:00");
	else if (strcmp(time_zone, "-1") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
	else if (strcmp(time_zone, "-2 1") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
	else if (strcmp(time_zone, "-2 2") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/03:00:00,M10.5.0/04:00:00");
	else if (strcmp(time_zone, "-2 3") == 0)
		strcpy(str_datnight, "PDT,M4.5.5/00:00:00,M9.5.5/00:00:00");
	else if (strcmp(time_zone, "-2 5") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/03:00:00,M10.5.5/04:00:00");
	else if (strcmp(time_zone, "-2 6") == 0)
		strcpy(str_datnight, "PDT,M3.5.5/02:00:00,M10.1.0/02:00:00");
	else if (strcmp(time_zone, "-3 2") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
	else if (strcmp(time_zone, "-4 2") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/04:00:00,M10.5.0/05:00:00");
	else if (strcmp(time_zone, "-9 4") == 0)
		strcpy(str_datnight, "PDT,M10.5.0/02:00:00,M4.1.0/03:00:00");
	else if (strcmp(time_zone, "-10 2") == 0)
		strcpy(str_datnight, "PDT,M10.5.0/02:00:00,M4.1.0/03:00:00");
	else if (strcmp(time_zone, "-10 4") == 0)
		strcpy(str_datnight, "PDT,M10.1.0/02:00:00,M4.1.0/03:00:00");
	else if (strcmp(time_zone, "-10 5") == 0)
		strcpy(str_datnight, "PDT,M3.5.0/02:00:00,M10.5.0/03:00:00");
	else if (strcmp(time_zone, "-12 1") == 0)
		strcpy(str_datnight, "PDT,M3.2.0/03:00:00,M10.1.0/02:00:00");
	else
		str_datnight[0] = '\0';

	//str_tz1 = gettoken((unsigned char *)time_zone, 0, ' ');
	sscanf(time_zone, "%s", str_tz1);
	if (strcmp(time_zone, "3 1") == 0 ||
	    strcmp(time_zone, "-3 4") == 0 ||
	    strcmp(time_zone, "-4 3") == 0 ||
	    strcmp(time_zone, "-5 3") == 0 ||
	    strcmp(time_zone, "-9 4") == 0 ||
	    strcmp(time_zone, "-9 5") == 0)
		yecho(TZ_FILE, "GMT%s:30%s\n", str_tz1, str_datnight);
	else
		yecho(TZ_FILE, "GMT%s%s\n", str_tz1, str_datnight);
}
#endif

int fget_and_test_pid(const char *filename)
{
	FILE *f;
	int pid;

	if ((f = fopen(filename, "r")) == NULL)
		return -1;
	if (fscanf(f, "%d", &pid) != 1 || kill(pid, 0))
		pid = 0;
	fclose(f);
	return pid;
}

void calc_use_data(char *ret_str, unsigned long data_h, unsigned long data_l)
{
	int len = 0;
	char tmpbuf[20];
	unsigned long data_octet[3];
	unsigned long giga = 1073741824;
	unsigned long mega = 1048576;
	unsigned long kilo = 1024;
	unsigned long mod_temp = 0;

	mod_temp = data_l;
	data_octet[2] = data_octet[1] = data_octet[0] = 0;

	if (data_h > 0)
		data_octet[0] = data_h * 4;
	if (data_l >= giga) {
		data_octet[0] += data_l / giga;
		mod_temp = data_l % giga;
	}
	if (mod_temp >= mega) {
		data_octet[1] = mod_temp / mega;
		mod_temp = mod_temp % mega;
	}
	if (mod_temp >= kilo)
		data_octet[2] = mod_temp / kilo;

	if (data_octet[0] > 0)
		len += snprintf(&tmpbuf[len], sizeof(tmpbuf) - len, "%luG ", data_octet[0]);
	if (data_octet[1] > 0)
		len += snprintf(&tmpbuf[len], sizeof(tmpbuf) - len, "%luM ", data_octet[1]);
	if (data_octet[2] > 0)
		len += snprintf(&tmpbuf[len], sizeof(tmpbuf) - len, "%luK", data_octet[2]);

	if (len == 0)
		len = sprintf(tmpbuf, "OK");

	sprintf(ret_str, "%sbyte", tmpbuf);
}

void telnet_make_rules(char *iface, int opmode, int fltd, int natd)
{
    /* Telnet rules are likely to be applied on the fly.
     * So it is necessary for the last excuted rules to be preserved.
     */
    char *pcmd = (natd > -1 && fltd > -1) ? NULL : "iptables -A";
	char *ip = nvram_safe_get("IP_ADDR");
	unsigned short telnet_port = (unsigned short)nvram_atoi("telnet_port", 2323);
	char wan_nip[32] = {0,};
	int telnet_enable;

	telnet_enable = nvram_atoi("telnet_enable", 0);
	if (telnet_enable == 0)
		return;

	if (natd > -1 && fltd > -1) {
		yfcat("/var/wan_ip", "%s", wan_nip);
		if ( strnlen(wan_nip, 30) < 6 ) {
			return;
		}

    	if (opmode == GATEWAY_MODE) {
    		dprintf(natd, "-A PREROUTING -i %s -p tcp -d %s --dport %hd -j DNAT --to %s:%hd\n", iface, wan_nip, telnet_port, ip, telnet_port);
			dprintf(fltd, "-A INPUT -i %s -p tcp -d %s --dport %hd -j TELNMS\n", iface, ip, telnet_port);
			//deny access by local
			dprintf(fltd, "-A INPUT -i br0 -p tcp --dport %hd -j DROP\n", telnet_port);
    	} else if (opmode == BRIDGE_MODE) {
			dprintf(fltd, "-A INPUT -p tcp -d %s --dport %hd -j TELNMS\n", wan_nip, telnet_port);
        }

        // telnet is eth1 all accept
		dprintf(fltd, "-I TELNMS -p tcp --dport %hd -j ACCEPT\n", telnet_port);
    }
}

int route_del_gateway(char *name)
{
	struct in_addr *gw = NULL;
	struct in_addr *p;
	unsigned long d, g;
	int flgs, i, n = 0;
	char interface[64];
	FILE *f = fopen("/proc/net/route", "r");

	if (!f)
		return 0;
	fscanf(f, "%*[^\n]\n");
	while (1) {
		if (fscanf(f, "%63s%lx%lx%X%*[^\n]\n", interface, &d, &g, &flgs) != 4)
			break;
		if ((name == NULL || !strcmp(interface, name)) &&
		    (d == 0 || (flgs & RTF_GATEWAY))) {
			p = (struct in_addr *)realloc(gw, sizeof(struct in_addr) * (n + 1));
			if (p == NULL)
				break;
			gw = p;
			gw[n++].s_addr = g;
		}
	}
	fclose(f);

	for (i = 0; i < n; i++)
		route_del(name, 0, "0.0.0.0", inet_ntoa(gw[i]), "0.0.0.0");
	if (gw)
		free(gw);
	return n;
}

char *read_line(const char *path, char *s, size_t size)
{
	FILE *f;

	s[0] = '\0';
	if ((f = fopen(path, "r"))) {
		fgets(s, size, f);
		fclose(f);
		ydespaces(s);
	}
	return s;
}

/* APACRTL-84  smlee 20151029 */
int get_repeater_mode(void)
{
	return (nvram_atoi("REPEATER_ENABLED1", 0) || nvram_atoi("REPEATER_ENABLED2", 0));
}

int run_fcommand(const char *path, const char *fmt, ...)
{
	va_list va;
	FILE *f;
	char buf[128], command[64];

	f = fopen(path, "r");
	if (f == NULL)
		return -1;
	va_start(va, fmt);
	vsnprintf(command, sizeof(command), fmt, va);
	va_end(va);

	while (fgets(buf, sizeof(buf), f)) {
		ydespaces(buf);
		//_exclp(NULL, "%s %s", command, buf);
		yexecl(NULL, "%s %s", command, buf);
	}
	fclose(f);
	return 0;
}

/* pos : 0 <= specifies the position from the first line of file
 *       -1 intended to delete line matched with cmd.
 */
int add_fcommand(const char *path, int pos, const char *pcmd, const char *fmt, ...)
{
	char tmp[] = "/var/XXXXXX";
	va_list ap;
	FILE *f, *t;
	char buf[128], *cmd;
	int len, n;

	va_start(ap, fmt);
	n = vasprintf((char **)&cmd, fmt, ap);
	va_end(ap);
	if (n < 0)
		return -1;
	if (pcmd)
		yexecl(NULL, "%s %s", pcmd, cmd);
	f = fopen(path, "r");
	if (f == NULL) {
		n = yecho(path, "%s\n", cmd);
		free(cmd);
		return n;
	}
	mktemp(tmp);
	t = fopen(tmp, "w+");
	if (t) {
		for (n = len = 0; fgets(buf, sizeof(buf), f);) {
			ydespaces(buf);
			if (!strcmp(buf, cmd))
				continue;
			if (n++ == pos)
				len = fprintf(t, "%s\n", cmd);
			fprintf(t, "%s\n", buf);
		}

		if (pos >= 0 && len == 0)
			fprintf(t, "%s\n", cmd);
		fclose(t);
	}
	fclose(f);
	if (t)
		rename(tmp, path);
	free(cmd);
	return 0;
}

int test_and_kill_pid(const char *pidfile, int signo)
{
	int pid = fget_and_test_pid(pidfile);
	if (pid > 0)
		kill(pid, signo);
	unlink(pidfile);
	return pid;
}

/* concatenate word with a separative blank character
 */
int strbcat(char *str, size_t size, int nodup, const char *word)
{
	size_t n, m;

	if (word[0] == '\0')
		return 0;

	n = strlen(str);
	if (nodup && n > 0) {
		char *p = strstr(str, word);
		if (p) {
			m = strlen(word);
			if (!strncmp(p, word, m) &&
			    (p[m] == '\0' || isspace(p[m])) &&
			    (p == str || isspace(p[-1]))) {
				return 0;
			}
		}
	}

	if (n < size) {
		m = snprintf(str + n, size - n, "%s%s", (n) ? " " : "", word);
		if (m < (size - n))
			return 0;
		str[n] = '\0';
	}

	return -1;
}

static struct iw_priv_args priv_set_mib;
#define IW_MAX_PRIV_DEF	128

static inline int iw_get_ext(int skfd, char *ifname, int request, struct iwreq *pwrq)
{
	strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
	return ioctl(skfd, request, pwrq);
}

static int iw_get_priv_fetch(int skfd, char *ifname, char *cmd)
{
	struct iw_priv_args *priv;
	struct iwreq wrq;
	int k;

	priv = (struct iw_priv_args *)malloc(sizeof(*priv) * IW_MAX_PRIV_DEF);
	if (priv == NULL)
		return -1;
	/* Ask the driver */
	wrq.u.data.pointer = (caddr_t) priv;
	wrq.u.data.length = IW_MAX_PRIV_DEF;
	wrq.u.data.flags = 0;
	if (iw_get_ext(skfd, ifname, SIOCGIWPRIV, &wrq) < 0)
		return (-1);
	/* Return the number of ioctls */
	for (k = 0; k < wrq.u.data.length; k++)
		if (!strcmp(priv[k].name, cmd)) {
			priv_set_mib = priv[k];
			break;
		}
	free(priv);
	return (k < wrq.u.data.length) ? 0 : -1;
}

int iwpriv_set_mib(char *ifname, const char *fmt, ...)
{
	int skfd = socket(AF_INET, SOCK_DGRAM, 0);
	int n, status = -1;
	struct iwreq wrq;
	va_list ap;

	if (skfd < 0)
		return -1;

	if (priv_set_mib.cmd == 0 && iw_get_priv_fetch(skfd, ifname, "set_mib")) {
		close(skfd);
		return -1;
	}

	memset(&wrq, 0, sizeof(wrq));

	va_start(ap, fmt);
	n = vasprintf((char **)&wrq.u.data.pointer, fmt, ap);
	va_end(ap);
	if (n < 0)
		goto out;

	wrq.u.data.length = n + 1;
	if (wrq.u.data.length > (priv_set_mib.set_args & IW_PRIV_SIZE_MASK)) {
		wrq.u.data.length = priv_set_mib.set_args & IW_PRIV_SIZE_MASK;
		((char *)wrq.u.data.pointer)[wrq.u.data.length - 1] = '\0';
	}

	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);
	status = ioctl(skfd, priv_set_mib.cmd, &wrq);
	free(wrq.u.data.pointer);
out:
	close(skfd);
	if (status)
		perror(__func__);
	return status;
}


int dotted_to_addr(const char *s, in_addr_t *addr)
{
	char tmp[32];
	char *q, *p = (char *)tmp;
	unsigned int l = 0;
	int i;

	snprintf(tmp, sizeof(tmp), "%s", s);
	ydespaces(tmp);

	for (i = 0; (q = strsep(&p, ".")); i++) {
		if (*q) {
			if (i < 4) {
				int n = (int)strtol(q, &q, 10);
				if (!*q && n >= 0 && n < 256)
					l |= ((unsigned char)n << ((3 - i) << 3));
				else
					break;
				continue;
			}
		}
		break;
	}

	if (i == 4) {
		*addr = htonl(l);
		return 0;
	}

	return -1;
}

in_addr_t nvram_inet_addr(char *name)
{
	char *p = nvram_get(name);
	in_addr_t addr;

	if (p && !dotted_to_addr(p, &addr))
		return addr;

	return INADDR_ANY;
}

static int parse_mask(char *mask, struct in_addr *maskaddr)
{
	unsigned int bits;
	char *endp;

	if (dotted_to_addr(mask, &maskaddr->s_addr)==0) {
		// if mask format is m.m.m.m
		return 0;
	}

	bits = strtoul(mask, &endp, 10);
	if (*endp != '\0' || bits > 32)
		return -1;
	if (bits != 0)
		maskaddr->s_addr = htonl(0xFFFFFFFF << (32 - bits));
	else
		maskaddr->s_addr = 0L;
	return 0;
}

int parse_proto_address(char *var, struct proto_addrs *paddr)
{
	int n;
	char *args[8];

	// parse x.x.x.x/m.m.m.m or x.x.x.x/num_bits
	n = ystrargs(var, args, 8, " ,\t\r\n", 0);
	if (n < 1)
		return -1;
	if (n > 1)
		paddr->port = htons(strtoul(args[1], NULL, 10));

	n = ystrargs(var, args, 8, "/", 0);
	if (n < 1)
		return -1;
	if (dotted_to_addr(args[0], &paddr->addr.s_addr))
		return -1;
	if (n > 1 && parse_mask(args[1], &paddr->mask))
		return -1;
	if (n == 1 && parse_mask("32", &paddr->mask))
		return -1;
	return 0;
}

#if defined(__DAVO_SSHD__)
void enable_sshd(int natd, int fltd)
{
    int opmode;
    /* Telnet rules are likely to be applied on the fly.
     * So it is necessary for the last excuted rules to be preserved.
     */
    char *pcmd = (natd > -1 && fltd > -1) ? NULL : "iptables -A";
	char *ip = nvram_safe_get("IP_ADDR");

    if (natd < 0 && !run_fcommand("/var/run/ipt_telnet", "iptables -D"))
        unlink("/var/run/ipt_telnet");

    apmib_get(MIB_OP_MODE, (void *)&opmode);
    if (opmode == GATEWAY_MODE) {
        if (natd > -1 && fltd > -1) {
            //dprintf(natd, "-A PREROUTING -p tcp --dport 22 -i eth1 -j DNAT --to %s:22\n", ip);
            dprintf(fltd, "-A INPUT -p tcp --dport 22 -d %s -j TELNMS\n", ip);
        } else {
            add_fcommand("/var/run/ipt_telnet", 0, pcmd,
                    "PREROUTING -t nat -p tcp --dport 22 -i eth1 -j DNAT --to %s:22", ip);
            add_fcommand("/var/run/ipt_telnet", 0, pcmd,
                    "INPUT -p tcp --dport 22 -d %s -j TELNMS", ip);
        }
    } else if (opmode == BRIDGE_MODE) {
        if (natd > -1 && fltd > -1) {
            //dprintf(natd, "-A PREROUTING -p tcp ! -d %s --dport 22 -i br0 -j DNAT --to %s:22\n", ip, ip);
            dprintf(fltd, "-A INPUT -p tcp -i br0 --dport 22 -j TELNMS\n");
        } else {
            add_fcommand("/var/run/ipt_telnet", 0, pcmd,
                    "PREROUTING -t nat -p tcp ! -d %s --dport 22 -i br0 -j DNAT --to %s:22", ip, ip);
            add_fcommand("/var/run/ipt_telnet", 0, pcmd,
                    "INPUT -p tcp -i br0 --dport 22 -j TELNMS");
        }
    }
}
#endif

void wl_connect_limit_count_set(void)
{
	int i, j, val;
	char name[24], path[32];

	for (i=0; i<NUM_WLAN_INTERFACE; i++) {
		for (j=0; j<NUM_VWLAN; j++) {
			if (j == 0) {
				snprintf(name, sizeof(name), "wlan%d_max_conn", i);
				snprintf(path, sizeof(path), "/proc/wlan%d/dv_max_count", i);
			} else {
				snprintf(name, sizeof(name), "wlan%d_vap%d_max_conn", i, j-1);
				snprintf(path, sizeof(path), "/proc/wlan%d-va%d/dv_max_count", i, j-1);
			}
			val = nvram_atoi(name, 10);
			yexecl(NULL, "sh -c \"echo %d > %s &\"", val, path);
		}
	}
}

void wl_port_shared_restrict(void)
{
	int i, j;
	int val;
	char prefix[12];
	char nvname[32], wlname[12];

	for (i=0; i<NUM_WLAN_INTERFACE; i++) {
		for (j=0; j<NUM_VWLAN; j++) {
			if (j == 0) {
				snprintf(prefix, sizeof(prefix), "WLAN%d", i);
				snprintf(wlname, sizeof(wlname), "wlan%d", i);
			} else {
				snprintf(prefix, sizeof(prefix), "WLAN%d_VAP%d", i, j-1);
				snprintf(wlname, sizeof(wlname), "wlan%d-va%d", i, j-1);
			}

			snprintf(nvname, sizeof(nvname), "%s_WLAN_DISABLED", prefix);
			if (nvram_match(nvname, "1"))
				continue;

			if (j == 0)
				snprintf(nvname, sizeof(nvname), "wlan%d_port_shared_restrict", i);
			else
				snprintf(nvname, sizeof(nvname), "wlan%d_vap%d_port_shared_restrict", i, j-1);

			if ((val = nvram_atoi(nvname, 0)) > 0)
				yexecl(NULL, "brctl setportrestrict br0 %s %d", wlname, val);
		}
	}
}

char *showApmsState(void)
{
	int val;

	if (yfcat(AUTOUP_STATE, "%d", &val) == 0 || val == 0) {
		return "대기중";
	} else {
		switch (val) {
			case 1:
				return "프로비전 정보 요청 중";
				break;
			case 2:
				return "프로비전 정보 다운로드 완료, 제조사 config 파일 요청";
				break;
			case 3:
				return "제조사 config 파일 완료, F/W 파일 요청";
				break;
			case 4:
				return "F/W 파일 다운 완료, 재부팅 대기 중";
				break;
			case 5:
				return "최신 펌웨어 사용 중";
				break;
			case 6:
				return "제조사 config 파일 완료, 재부팅 대기 중";
				break;
			default:
				return "---";
				break;
		}
	}
}

static inline int same_network(in_addr_t ip, in_addr_t mask, in_addr_t ip2, in_addr_t mask2)
{
	in_addr_t mask3;

	if (mask > mask2)
		mask3 = mask;
	else
		mask3 = mask2;

	return ((ip & mask3) == (ip2 & mask3));
}

/*
 * < 0	mask was not a decent combination of 1's and 0's
 */
static int prefix_length(const in_addr_t mask)
{
	int i;
	u_int32_t maskaddr, bits;

	maskaddr = ntohl(mask);
	if (maskaddr == 0xFFFFFFFFL)
		return 32;
	i = 32;
	bits = 0xFFFFFFFEL;
	while (--i >= 0 && maskaddr != bits)
		bits <<= 1;
	return i;
}

static int compare_default_network(in_addr_t wanip, in_addr_t wanmask, in_addr_t lanip, in_addr_t lanmask)
{
	char defip[20], defmask[20], defstart[20], defend[20];
	in_addr_t def_lanip, def_lanmask;

	nvram_get_r_def("user_ip", defip, sizeof(defip), "192.168.200.254");
	nvram_get_r_def("SUBNET_MASK", defmask, sizeof(defmask), "255.255.255.0");

	inet_aton(defip, (struct in_addr *)&def_lanip);
	inet_aton(defmask, (struct in_addr *)&def_lanmask);

	if (!same_network(lanip, lanmask, def_lanip, def_lanmask)) {
		if (!same_network(wanip, wanmask, def_lanip, def_lanmask)) {
			nvram_get_r_def("user_dhcp_start", defstart, sizeof(defstart), "192.168.200.100");
			nvram_get_r_def("user_dhcp_end", defend, sizeof(defend), "192.168.200.200");
			nvram_set("IP_ADDR", defip);
			nvram_set("DHCP_CLIENT_START", defstart);
			nvram_set("DHCP_CLIENT_END", defend);
			syslog(LOG_INFO, "Gateway 복구 %u.%u.%u.%u -> %u.%u.%u.%u 변경", NIPQUAD(lanip), NIPQUAD(def_lanip));
			nvram_commit();
			yexecl(NULL, "reboot");
			return 1;
		}
	}

	return 0;
}

static in_addr_t calc_new_network(const in_addr_t ip, const in_addr_t mask, const in_addr_t tip, const in_addr_t tmask)
{
	uint8_t *p;
	in_addr_t tmp, tmp2, subnet;
	int m, n;

	if ((m = prefix_length(mask)) <= 0)
		return 0;

	tmp = tip;
	n = prefix_length(tmask);
	/* if WAN's mask is smaller than LAN's, select the mask of LAN */
	m = (m < n) ? m : n;
	if (m & 7) {
		tmp = ntohl(tmp);
		tmp >>= (32 - m);
		--tmp;
		tmp <<= (32 - (m & 7));
		tmp >>= (m & ~7);
		tmp2 = ntohl(tip);
		tmp2 >>= (32 - (m & ~7));
		tmp2 <<= (32 - (m & ~7));
		tmp = tmp + tmp2 + 1;
		tmp = htonl(tmp);
	} else if (m > 0) {
		p = &((uint8_t *)&tmp)[(m - 1) >> 3];
		--*p;
	}

	subnet = tmp & tmask;
	if (subnet != tmp && (subnet ^ tmp) != ~tmask &&
	    !same_network(ip, mask, tmp, tmask))
		return tmp;
	return 0;
}

void avoid_same_network(in_addr_t wanip, in_addr_t wanmask)
{
	in_addr_t lanip, lanmask;
	in_addr_t zeros, allones, clntstart, clntend;
	in_addr_t tmp, tmp1;
	char ipval[16];

	apmib_get(MIB_IP_ADDR, (void *)&lanip);
	apmib_get(MIB_SUBNET_MASK, (void *)&lanmask);

	if ((lanip & lanmask) && (wanip & wanmask)) {
		if (same_network(wanip, wanmask, lanip, lanmask)) {
			if (compare_default_network(wanip, wanmask, lanip, lanmask))
				return;
			tmp = calc_new_network(wanip, wanmask, lanip, lanmask);
			if (tmp) {
				zeros = tmp & lanmask;
				allones = (tmp & lanmask) + ~lanmask;

				nvram_get_r("user_dhcp_start", ipval, sizeof(ipval));
				tmp1 = inet_addr(ipval) & 0xff000000;
				clntstart = (zeros & 0x00ffffff) | tmp1;
				nvram_get_r("user_dhcp_end", ipval, sizeof(ipval));
				tmp1 = inet_addr(ipval) & 0xff000000;
				clntend = (allones & 0x00ffffff) | tmp1;

				if (htonl(clntstart) > htonl(clntend))
					return;

				apmib_set(MIB_IP_ADDR, &tmp);
				syslog(LOG_INFO, "Gateway 충돌 %u.%u.%u.%u -> %u.%u.%u.%u 변경", NIPQUAD(lanip), NIPQUAD(tmp));
				sprintf(ipval, "%u.%u.%u.%u", NIPQUAD(clntstart));
				nvram_set("DHCP_CLIENT_START", ipval);
				sprintf(ipval, "%u.%u.%u.%u", NIPQUAD(clntend));
				nvram_set("DHCP_CLIENT_END", ipval);
				nvram_commit();
				yexecl(NULL, "reboot");
			}
		} else
			compare_default_network(wanip, wanmask, lanip, lanmask);
	}
}

#define CHECK_WANIP "/tmp/.wan_ip_change"
void check_change_wanip(char *new_ip)
{
	int changed = 0;
	char old_ip[16];
	int snmptrap_pid = fget_and_test_pid("/var/run/snmp_trapd.pid");

	if (strncmp(new_ip, "0.0.0.0", 7) == 0)
		return;

	if (access(VAR_WAN_IP_FILE, F_OK) == 0) {
		if (access(CHECK_WANIP, F_OK) == 0) {
			yfcat(CHECK_WANIP, "%s", old_ip);
			if (strcmp(old_ip, new_ip)) {
				changed = 1;
				yecho(CHECK_WANIP, "%s", new_ip);
			}
		} else
			yecho(CHECK_WANIP, "%s", new_ip);
	}

	if (snmptrap_pid > 0 && changed == 1)
		yecho("/tmp/wan_ip_change", "1");
}
