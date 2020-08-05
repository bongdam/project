#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
//#include <linux/dvflag.h>
#include <linux/route.h>
#include <sys/inotify.h>
#include <limits.h>
#include <sys/syscall.h>
#include "../include/dvflag.h"

#ifndef IF_PREFIX_ONLINK
#define IF_PREFIX_ONLINK	0x01
#define IF_PREFIX_AUTOCONF	0x02
#endif

#define DEVNAME     "/proc/dvflag"

extern char *if_indextoname(unsigned ifindex, char *ifname);
extern unsigned int if_nametoindex(const char *ifname);

static char wan_ifc[IFNAMSIZ];
static int sdmz_mode;
static int verbose = 0;
static int autoconf = 0;
static unsigned int if_flags = 0;

#define dprint( ... )				\
	do {					\
		if (verbose)		\
			printf(__VA_ARGS__);	\
	} while(0)

#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif

enum {
	NET_LINKDOWN = -1,
	NET_LINKUP
};

struct rt_gateway {
	char devname[64];
	struct in_addr gateway;
};

static int rtfetch_gateway(struct rt_gateway *r, int len)
{
	unsigned long d, g, m;
	int flgs, ref, use, metric, mtu, win, ir;
	int npos = 0;
	FILE *fp;

	if (len < 1)
		return 0;

	fp = fopen("/proc/net/route", "r");
	if (!fp)
		return 0;

	fscanf(fp, "%*[^\n]\n");
	while (1) {
		if (fscanf(fp, "%63s%lx%lx%X%d%d%d%lx%d%d%d\n",
			   r[npos].devname, &d, &g, &flgs, &ref, &use, &metric,
			   &m, &mtu, &win, &ir) != 11)
			break;

		if (flgs & RTF_GATEWAY) {
			if (npos < len)
				r[npos++].gateway.s_addr = g;
			else
				break;
		}
	}
	fclose(fp);
	return npos;
}

static int rtnetlink(const char *ifname)
{
	int fd, status = NET_LINKDOWN;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return NET_LINKDOWN;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (!ioctl(fd, SIOCGIFFLAGS, &ifr) && (ifr.ifr_flags & IFF_UP))
		status = NET_LINKUP;
	close(fd);
	return status;
}

static int rtnetaddress(const char *ifname, struct in_addr *in)
{
	int fd, res;
	struct ifreq ifr;

	in->s_addr = INADDR_ANY;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;
	strcpy(ifr.ifr_name, ifname);
	if ((res = ioctl(fd, SIOCGIFADDR, &ifr)) == 0)
		*in = ((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr;
	close(fd);
	return res;
}

static long monotonic_ms(void)
{
	struct timespec ts;
	syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &ts);
	return (long)(ts.tv_sec * 1000UL + ts.tv_nsec / 1000000);
}

static int write_flag(const char *ifname, int bset, unsigned int flgs, int bforce)
{
#define MAX_WAITMS      2000L
#define UNIT_WAITUS     500000L
	int fd;
	long stime;
	unsigned int cmd[2];
	struct rt_gateway r[2];

	fd = open(DEVNAME, O_RDWR);
	if (fd != -1) {
		read(fd, (void *)&cmd[0], sizeof(int));
		if (bforce || (((cmd[0] & flgs) && !bset) || (!(cmd[0] & flgs) && bset))) {
			cmd[0] = (bset) ? flgs : 0;
			cmd[1] = flgs;

			if (flgs == DF_WANBOUND && bset) {
				/* wait for MAX_WAITMS milisecs till network can be routable */
				stime = monotonic_ms();
				do {
					usleep(UNIT_WAITUS);
					if (rtfetch_gateway(r, sizeof(r) / sizeof(r[0])) > 0 &&
					    !strcasecmp(r[0].devname, ifname))
						break;
				} while ((long)(monotonic_ms() - stime) < MAX_WAITMS);
			}
			dprint("write dvflag 0x%X, 0x%X\n", cmd[0], cmd[1]);
			write(fd, cmd, sizeof(cmd));
		}
		close(fd);
		return 0;
	}
	return -1;
}

static void sighandler(int signo)
{
	verbose = !verbose;
	dprint("sdmz=%d WAN=%s\n", sdmz_mode, wan_ifc);
}

static void update_flgs(const char *ifname, struct in_addr *old,
			unsigned int flgs)
{
	char buf[80];
	FILE *f;
	struct in_addr ip;
	int bound = 0, uncond = FALSE;

	if (rtnetlink(ifname) == NET_LINKUP) {
		if (sdmz_mode) {
			if ((f = fopen("/var/wan_ip", "r"))) {
				buf[0] = 0;
				fgets(buf, sizeof(buf), f);
				if (inet_aton(buf, &ip) && ip.s_addr && ip.s_addr != INADDR_NONE)
					bound = 1;
				fclose(f);
			}
		} else {
			if ((!rtnetaddress(ifname, &ip) && ip.s_addr
			     && ip.s_addr != INADDR_NONE)) {
				bound = 1;
			}
		}
	}

	if (bound) {
		if (old->s_addr != ip.s_addr) {
			uncond = TRUE;
			*old = ip;
		}
	} else
		old->s_addr = 0;

	dprint("bound=%d flgs=%u, uncond=%d old->s_addr=0x%X\n", bound,
	       flgs, uncond, old->s_addr);
	write_flag(ifname, bound, flgs, uncond);
}

static int print_prefix(struct nlmsghdr *nlh)
{
	struct prefixmsg *prefix = NLMSG_DATA(nlh);
	int len = nlh->nlmsg_len;
	struct rtattr *rta;
	struct prefix_cacheinfo *pc;
	char tmp[64];

	len -= NLMSG_LENGTH(sizeof(*prefix));
	if (len < 0)
		return -1;

	for (rta = RTM_RTA(prefix); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if (rta->rta_type == PREFIX_ADDRESS)
			fprintf(stderr, "prefix %s/%d ",
				inet_ntop(AF_INET6, RTA_DATA(rta), tmp, sizeof(tmp)),
				prefix->prefix_len);
	}

	fprintf(stderr, "dev %s %s%s",
		if_indextoname(prefix->prefix_ifindex, tmp),
		(prefix->prefix_flags & IF_PREFIX_ONLINK) ? "onlink " : "",
		(prefix->prefix_flags & IF_PREFIX_AUTOCONF) ? "autoconf " : "");

	for (rta = RTM_RTA(prefix); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if (rta->rta_type == PREFIX_CACHEINFO) {
			pc = (struct prefix_cacheinfo *)RTA_DATA(rta);
			fprintf(stderr, "valid %u preferred %u",
				pc->valid_time, pc->preferred_time);

		}
	}

	fputc('\n', stderr);
	return 0;
}

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

#define IF_RA_OTHERCONF	0x80
#define IF_RA_MANAGED	0x40
#define IF_RA_RCVD	0x20
#define IF_RS_SENT	0x10

#define DHCP6C_PIDFILE	"/var/lib/dhcp6/dhcp6c.pid"

static int in6_prefix(struct nlmsghdr *nlh, unsigned int *prevflg)
{
	struct prefixmsg *prefix = NLMSG_DATA(nlh);
	int client6_pid, timeout;

	if (prefix->prefix_family != AF_INET6)
		return -1;

	if (autoconf) {
		client6_pid = fget_and_test_pid(DHCP6C_PIDFILE);

		if (prefix->prefix_pad2 & IF_RA_MANAGED) {
			if ((*prevflg & (IF_RA_OTHERCONF | IF_RA_MANAGED))
			    == IF_RA_OTHERCONF && client6_pid > 0)
				client6_pid = kill(client6_pid, SIGKILL);

			if (client6_pid <= 0)
				system("sysconf -6 br0 2");
		} else {
			if ((*prevflg & (IF_RA_OTHERCONF | IF_RA_MANAGED))
			    == IF_RA_MANAGED && client6_pid > 0) {
				kill(client6_pid, SIGTERM);
				if (prefix->prefix_pad2 & IF_RA_OTHERCONF) {
					for (timeout = 1000 * 1000;
					     timeout >= 0; timeout -= (200 * 1000)) {
						usleep(200 * 1000);
						if (!kill(client6_pid, 0))
							break;
					}
					dprint("wait for dhcp6c to exit (%d)\n", timeout);
					if (timeout <= 0)
						kill(client6_pid, SIGKILL);
				}
				client6_pid = 0;
			}

			if (client6_pid <= 0 && prefix->prefix_pad2 & IF_RA_OTHERCONF)
				system("sysconf -6 br0 0");
		}
	}

 	*prevflg = prefix->prefix_pad2;
	if (verbose)
		print_prefix(nlh);
	return 0;
}

struct msg_type {
	unsigned short type;
	int (* func)(struct nlmsghdr *, void *);
};

static int dad_fail(struct nlmsghdr *nlh, void *unused)
{
	char tmp[32];
	int pid;
	struct ifaddrmsg *amsg = (struct ifaddrmsg *)NLMSG_DATA(nlh);

	if (amsg->ifa_family == AF_INET6) {
		if (nlh->nlmsg_type == RTM_NEWADDR &&
		    amsg->ifa_flags & IFA_F_DADFAILED) {
			syslog(LOG_WARNING, "%s: inet6 duplicate address dectected!",
			       if_indextoname(amsg->ifa_index, tmp));
			closelog();
			pid = fget_and_test_pid(DHCP6C_PIDFILE);
			if (pid > 0)
				kill(pid, SIGUSR1);
			return 0;
		}
	}

	return -1;
}

static int prefix_new(struct nlmsghdr *nlh, void *unused)
{
	in6_prefix(nlh, &if_flags);
	return 0;
}

static int addr_type(struct nlmsghdr *nlh, void *arg)
{
	struct ifaddrmsg *amsg = (struct ifaddrmsg *)NLMSG_DATA(nlh);

	if (dad_fail(nlh, arg) && amsg->ifa_family != AF_INET6
	    && amsg->ifa_index == if_nametoindex(wan_ifc))
		update_flgs(wan_ifc, arg, DF_WANBOUND);
	return 0;
}

static int link_type(struct nlmsghdr *nlh, void *arg)
{
	struct ifinfomsg *imsg = (struct ifinfomsg *)NLMSG_DATA(nlh);

	if (imsg->ifi_index == if_nametoindex(wan_ifc))
		update_flgs(wan_ifc, arg, DF_WANBOUND);
	return 0;
}

static int nl_dispatch(int s, const struct msg_type *types, void *arg)
{
	char buf[2000];
	struct sockaddr_nl remote;
	struct nlmsghdr *nlh;
	int addrlen, err;
	const struct msg_type *p;

	addrlen = sizeof(remote);
	err = recvfrom(s, buf, sizeof(buf), 0,
		       (struct sockaddr *)&remote, &addrlen);
	if (err <= 0 || addrlen != sizeof(remote)) {
		fprintf(stderr, "%s: rcvlen %d\n", __func__, err);
		return -1;
	}

	nlh = (struct nlmsghdr *)buf;
	for (; NLMSG_OK(nlh, err); nlh = NLMSG_NEXT(nlh, err)) {
		for (p = types; p->func; p++) {
			if (p->type == nlh->nlmsg_type) {
				dprint("nlh->nlmsg_type=%d\n", nlh->nlmsg_type);
				p->func(nlh, arg);
				break;
			}
		}
	}

	return 0;
}

static int inotify_dispatch(int s, struct in_addr *ip)
{
#define BUF_LEN		(10 * (sizeof(struct inotify_event) + NAME_MAX + 1))
	char buf[BUF_LEN] __attribute__ ((aligned(4)));
	ssize_t len;
	char *p;
	struct inotify_event *i;

	len = read(s, buf, BUF_LEN);
	if (len <= 0) {
		perror(__func__);
		return -1;
	}

	for (p = buf; p < (buf + len);) {
		i = (struct inotify_event *)p;
		dprint("%s: %.*s\n", __func__, i->len, i->name);
		if ((i->mask & (IN_CLOSE_WRITE|IN_ISDIR)) == IN_CLOSE_WRITE &&
		    i->len > 0 && !strcmp(i->name, "wan_ip"))
			update_flgs(wan_ifc, ip, DF_WANBOUND);
		p += (sizeof(*i) + i->len);
	}

	return 0;
}

static void say_error_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	vfprintf(stderr, s, p);
	va_end(p);
	exit(EXIT_FAILURE);
}

static struct msg_type nltypes[] = {
	{ RTM_NEWADDR,		addr_type },
	{ RTM_DELADDR,		addr_type },
	{ RTM_NEWLINK,		link_type },
	{ RTM_DELLINK,		link_type },
	{ RTM_NEWPREFIX,	prefix_new },
	{ 0,			NULL	  }
};

static struct msg_type nltypes6[] = {
	{ RTM_NEWADDR,		dad_fail   },
	{ RTM_NEWPREFIX,	prefix_new },
	{ 0,			NULL	   }
};

int main(int argc, char **argv)
{
	fd_set rfds;
	int nh, ih = -1;
	struct sockaddr_nl local;
	int opt;
	struct in_addr ip[2];
	const struct msg_type *p;

	while ((opt = getopt(argc, argv, "i:vsa:")) != -1) {
		switch (opt) {
		case 'i':
			snprintf(wan_ifc, sizeof(wan_ifc), "%s", optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'a':
			autoconf = !strtol(optarg, NULL, 10);
			break;
		case 's':
			sdmz_mode = 1;
			break;
		default:
			say_error_and_die("Usage: sysmgmtd [options]\n"
					  "-i inf  WAN interface name\n"
					  "-s      Super DMZ mode\n"
					  "-a      Autoconfiguration\n"
					  "-v      Verbose.\n");
		}
	}

	if (wan_ifc[0] == '\0')
		say_error_and_die("%s: Need valid interface\n", argv[0]);

	signal(SIGUSR1, sighandler);
	memset(ip, 0, sizeof(ip));

	nh = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nh == -1)
		say_error_and_die("socket");

	bzero(&local, sizeof(local));
	local.nl_family = AF_NETLINK;
	//local.nl_pad = 0;
	local.nl_pid = getpid();
	local.nl_groups = RTMGRP_IPV6_PREFIX|RTMGRP_IPV6_IFADDR;
	if (sdmz_mode == 0)
		local.nl_groups |= (RTMGRP_IPV4_IFADDR|RTMGRP_NOTIFY|RTMGRP_LINK);

	if (bind(nh, (struct sockaddr *)&local, sizeof(local)))
		say_error_and_die("bind");

	if (sdmz_mode) {
		ih = inotify_init();	/* Create inotify instance */
		if (ih == -1)
			say_error_and_die("inotify_init: %s\n", strerror(errno));
		if (inotify_add_watch(ih, "/var", IN_CLOSE_WRITE) < 0)
			say_error_and_die("inotify_add_watch");
		p = nltypes6;
	} else
		p = nltypes;

	while (1) {
		FD_ZERO(&rfds);
		FD_SET(nh, &rfds);
		if (ih > -1)
			FD_SET(ih, &rfds);

		switch (select(1 + ((nh > ih) ? nh : ih), &rfds, NULL, NULL, NULL)) {
		case -1:
			if (errno != EINTR)
				say_error_and_die("%s\n", strerror(errno));
		case 0:
			break;
		default:
			if (FD_ISSET(nh, &rfds))
				nl_dispatch(nh, p, (void *)ip);

			if (ih > -1 && FD_ISSET(ih, &rfds))
				inotify_dispatch(ih, ip);
			break;
		}
	}

	return 0;
}
