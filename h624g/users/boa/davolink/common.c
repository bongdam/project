#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/route.h>
#include <signal.h>
#include "apmib.h"
#include "custom.h"

int strtoi(const char *s, int *ret)
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

void enable_telnet(void)
{
	int opmode;
	char lan_nip[30];

	apmib_get(MIB_OP_MODE, (void *)&opmode);
	nvram_get_r("IP_ADDR", lan_nip, sizeof(lan_nip));

	if (opmode == GATEWAY_MODE) {
		yexecl("2>/dev/null", "iptables -t nat -D PREROUTING -p tcp --dport 6000 -i eth1 -j DNAT --to %s:6000", lan_nip);
		yexecl("2>/dev/null", "iptables -D INPUT -p tcp --dport 6000 -d %s -j ACL", lan_nip);
		yexecl(NULL, "iptables -t nat -A PREROUTING -p tcp --dport 6000 -i eth1 -j DNAT --to %s:6000", lan_nip);
		yexecl(NULL, "iptables -A INPUT -p tcp --dport 6000 -d %s -j ACL", lan_nip);
	} else if (opmode == BRIDGE_MODE) {
		yexecl("2>/dev/null", "iptables -t nat -D PREROUTING -p tcp ! -d %s --dport 6000 -i br0 -j DNAT --to %s:6000", lan_nip, lan_nip);
		yexecl("2>/dev/null", "iptables -D INPUT -p tcp -i br0 --dport 6000 -j ACL");
		yexecl(NULL, "iptables -t nat -A PREROUTING -p tcp ! -d %s --dport 6000 -i br0 -j DNAT --to %s:6000", lan_nip, lan_nip);
		yexecl(NULL, "iptables -A INPUT -p tcp -i br0 --dport 6000 -j ACL");
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
