#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bcmnvram.h>
#include <libytool.h>
#include "config.h"

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static const char upnpdpid[] =  "/var/run/miniupnpd.pid";
static const char upnpd[] = "miniupnpd";
static const char upnpdconf[] = "/var/miniupnpd.conf";
static char uuid[] = "c3a9674f-c4ba-4e99-8984-f084deaebe51";
static char serial[64] = "12345678901234567890";

static int increase_entropy(void)
{
	return 0;
}

#define seeding()	time(NULL)

static int fget_and_test_pid(const char *filename)
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

static char *trim_space(char *s)
{
	int len = strlen(s);
	/* trim trailing whitespace and double quotation */
	while (len > 0 && (isspace(s[len - 1]) || s[len - 1] == '"'))
		s[--len] = '\0';
	/* trim trailing whitespace and double quotation */
	memmove(s, &s[strspn(s, " \n\r\t\v\"")], len);
	return s;
}

static int getvar(const char *name, const char *dfl,
		char *buf, unsigned int bsiz, const char *path)
{
	FILE *f = NULL;
	char tmp[128];
	int len;

	if (buf == NULL || bsiz == 0 || name == 0 || (len = strlen(name)) == 0)
		return -1;

	*buf = 0;

	if (path == 0 || *path == 0)
		goto defaults;

	if ((f = fopen(path, "r")) != 0) {
		while (fgets(tmp, sizeof(tmp), f) != NULL) {
			trim_space(tmp);
			if (!strncmp(tmp, name, len)) {
				if (isspace(tmp[len]))
					trim_space(&tmp[len]);

				if (isspace(tmp[len + 1]))
					trim_space(&tmp[len + 1]);

				if (tmp[len] == '=' && tmp[len + 1] != '\0') {
					snprintf(buf, bsiz, "%s", &tmp[len + 1]);
					dfl = NULL;
				}
				break;
			}
		}
		fclose(f);
	}

 defaults:
	if (dfl)
		snprintf(buf, bsiz, "%s", dfl);
	return strlen(buf);
}

static void usage(void)
{
	printf("Usage: upnpctrl [-m MAC -s serial-number] <up|down> [<external ifname> <internal ifname>]\n");
	printf("       upnpctrl -m 00:08:52:11:22:33 -s 12345 up eth1 br0\n");
	printf("       upnpctrl down\n");
	printf("       upnpctrl sync\n");
	exit(-1);
}

struct inet_params {
	int local_port, rem_port, state, uid;
	struct sockaddr_in localaddr, remaddr;
	unsigned long rxq, txq, inode;
};

static int scan_inet_proc_line(struct inet_params *param, char *line)
{
	int num;
	char local_addr[64], rem_addr[64];

	num = sscanf(line,
			"%*d: %63[^:]:%X "
			"%63[^:]:%X %X "
			"%lX:%lX %*X:%*X "
			"%*X %d %*d %ld ",
			local_addr, &param->local_port,
			rem_addr, &param->rem_port, &param->state,
			&param->txq, &param->rxq,
			&param->uid, &param->inode);
	if (num < 9)
		return 1; /* error */
	return 0;
}

static int tcp_port_state(u_int16_t port, unsigned mask)
{
	FILE *f;
	char buf[160];
	struct inet_params param;

	f = fopen("/proc/net/tcp", "r");
	if (f != NULL) {
		while (fgets(buf, sizeof(buf), f)) {
			if (!scan_inet_proc_line(&param, buf) &&
			    (param.local_port == port) &&
			    (param.state & mask)) {
				fclose(f);
				return 0;
			}
		}
		fclose(f);
	}
	return -1;
}

static u_int16_t rand_listen_port(void)
{
	u_int16_t port;
	int n;

	increase_entropy();
	srand(seeding());
	for (n = 0; n < 3; n++) {
		port = (u_int16_t)((rand() % 0x7fff) + 0x7fff);
		if (tcp_port_state(port, 0x02))
			return port;
	}

	return (u_int16_t)((rand() % 0x7fff) + 0x7fff);
}

static int getifaddr4(const char *name, struct in_addr *ip)
{
	struct ifreq ifr;
	int s, status;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, name);
	if ((status = ioctl(s, SIOCGIFADDR, &ifr)) == 0)
		*ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	close(s);
	return status;
}

static int upnpd_up(const char *ext_ifname, const char *int_ifname)
{
	unsigned short port;
	struct in_addr ext_ip;
	FILE *f;
#ifdef LEASE_WRITE_THRU
	char buf[16];
#endif
#ifdef ENABLE_MANUFACTURER_INFO_CONFIGURATION
	char hostname[64] = { 0 };
	const char *maker = "Seiko Solutions Inc.";
#endif
	if (!ext_ifname || !ext_ifname[0] || !int_ifname || !int_ifname[0])
		return -1;

	port = rand_listen_port();
	if (getifaddr4(ext_ifname, &ext_ip)) {
		perror(__func__);
		return -1;
	}
#ifdef ENABLE_MANUFACTURER_INFO_CONFIGURATION
	gethostname(hostname, sizeof(hostname));
#endif
	f = fopen(upnpdconf, "w");
	if (f == NULL) {
		perror(upnpdconf);
		return -1;
	}

	fprintf(f,
	     "ext_ifname=%s\n"
	     "ext_ip=%u.%u.%u.%u\n"
	     "listening_ip=%s\n"
	     "port=%u\n"
	     "enable_natpmp=no\n"
	     "enable_upnp=yes\n"
	     "secure_mode=yes\n"
	     "system_uptime=yes\n"
	     "notify_interval=60\n"
	     "clean_ruleset_interval=600\n"
	     "uuid=%s\n"
	     "serial=%s\n"
	     "model_number=1\n",
	     ext_ifname,	/* ext_ifname	*/
	     NIPQUAD(ext_ip),	/* ext_ip	*/
	     int_ifname,	/* listening_ip	*/
	     port,		/* port		*/
	     uuid,
	     serial);
#ifdef LEASE_WRITE_THRU
	yfcat("/var/miniupnpd_opt", "%*s %s", buf);
	fprintf(f, "leased_only=%s\n", buf);
	unlink("/var/miniupnpd_opt");
#endif
#ifdef ENABLE_MANUFACTURER_INFO_CONFIGURATION
	if (hostname[0])
		fprintf(f, "friendly_name=%s %s\n"
			   "manufacturer_name=%s\n"
			   "manufacturer_url=https://www.seiko-sol.co.jp/\n"
			   "model_name=%s\n"
			   "model_description=%s %s\n"
			   "model_url=https://www.seiko-sol.co.jp/\n",
			maker, hostname, maker, hostname, maker, hostname);
#endif
	fclose(f);
	yexecl(NULL, "route add -net 239.255.255.250 netmask 255.255.255.255 br0");
	yexecl(NULL, "iptables -I INPUT -p tcp --dport %u -j ACCEPT", port);
	yexecl(NULL, "iptables -t nat -N MINIUPNPD");
	yexecl(NULL, "iptables -t nat -A PREROUTING -d %u.%u.%u.%u -i %s -j MINIUPNPD", NIPQUAD(ext_ip), ext_ifname);
	yexecl(NULL, "iptables -N MINIUPNPD");
	yexecl(NULL, "iptables -I FORWARD -i %s ! -o %s -j MINIUPNPD", ext_ifname, ext_ifname);

	return yexecl(NULL, "miniupnpd -f %s", upnpdconf);
}

static int upnpd_down(void)
{
	char buf[80], buf2[80];
	unsigned int port;

	yexecl("2>/dev/null", "killall -TERM %s", upnpd);
	yexecl("2>/dev/null", "route del -net 239.255.255.250 netmask 255.255.255.255 br0");

	getvar("port", NULL, buf, sizeof(buf), upnpdconf);
	port = strtoul(buf, NULL, 10);
	if (port > 0)
		yexecl(NULL, "iptables -D INPUT -p tcp --dport %u -j ACCEPT", port);

	getvar("ext_ifname", NULL, buf, sizeof(buf), upnpdconf);
	getvar("ext_ip", NULL, buf2, sizeof(buf2), upnpdconf);
	if (buf[0] && buf2[0])
		yexecl(NULL, "iptables -t nat -D PREROUTING -d %s -i %s -j MINIUPNPD",
		       buf2, buf);

	yexecl("2>/dev/null", "iptables -t nat -F MINIUPNPD");
	yexecl("2>/dev/null", "iptables -t nat -X MINIUPNPD");
	if (buf[0])
		yexecl(NULL, "iptables -D FORWARD -i %s ! -o %s -j MINIUPNPD", buf, buf);
	yexecl("2>/dev/null", "iptables -F MINIUPNPD");
	yexecl("2>/dev/null", "iptables -X MINIUPNPD");
	unlink(upnpdconf);
	return 0;
}

static int ether_atoe(const char *s, unsigned char *addr)
{
	char tmp[32];
	char *q, *p = (char *)tmp;
	int i;

	snprintf(tmp, sizeof(tmp), "%s", s);
	for (i = 0; (q = strsep(&p, ":-")); i++) {
		if (*q) {
			if (i < 6) {
				int n = (int)strtol(q, &q, 16);
				if (!*q && n >= 0 && n < 256)
					*addr++ = (unsigned char)n;
				else
					break;
				continue;
			}
		}
		break;
	}

	return (i == 6) ? 0 : -1;
}

int main(int argc, char *argv[])
{
	char buf[80], buf2[80];
	unsigned char haddr[6];
	int opt;

	memset(haddr, 0, sizeof(haddr));
	while ((opt = getopt(argc, argv, "m:s:")) != -1) {
		switch (opt) {
			case 'm':
				if (ether_atoe(optarg, haddr)) {
					fprintf(stderr, "Invalid MAC address: %s\n", optarg);
					exit(-1);
				}
				break;
			case 's':
				snprintf(serial, sizeof(serial), "%s", optarg);
				break;
			default:
				usage();
		}
	}

	sprintf(&uuid[8 + 4 + 4 + 4 + 4], "%02x%02x%02x%02x%02x%02x",
			haddr[0], haddr[1], haddr[2], haddr[3], haddr[4], haddr[5]);

	if ((optind + 2) < argc && !strcmp(argv[optind], "up")) {
		if (fget_and_test_pid(upnpdpid) > 0)
			return 0;
		// sanity check
		if (!strcmp(argv[optind + 1], argv[optind + 2]) ||
				!if_nametoindex(argv[optind + 1]) || !if_nametoindex(argv[optind + 2])) {
			fprintf(stderr, "Invalid interface: %s %s\n",
					argv[optind + 1], argv[optind + 2]);
			exit(-1);
		} else
			return upnpd_up(argv[optind + 1], argv[optind + 2]);
	} else if (optind < argc && !strcmp(argv[optind], "down")) {
		upnpd_down();
	} else if (argc == 2 && !strcmp(argv[1], "sync")) {
		getvar("ext_ifname", NULL, buf, sizeof(buf), upnpdconf);
		getvar("listening_ip", NULL, buf2, sizeof(buf2), upnpdconf);
		upnpd_down();
		upnpd_up(buf, buf2);
	} else
		usage();
	return 0;
}
