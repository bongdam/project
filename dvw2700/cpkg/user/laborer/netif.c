#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <dvflag.h>
#include "select_event.h"
#include "fifoserve.h"
#include "cmd.h"
#include "instrument.h"

#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif
#ifndef IF_PREFIX_ONLINK
#define IF_PREFIX_ONLINK	0x01
#define IF_PREFIX_AUTOCONF	0x02
#endif

extern size_t strlcpy(char *dst, const char *src, size_t siz);
extern unsigned int if_nametoindex(const char *ifname);
extern char *if_indextoname(unsigned int ifindex, char *ifname);
#ifndef NDEBUG
static int print_route(struct rtmsg *r, struct nlmsghdr *n);
#endif

static int verbose;
static struct in_addr nif_addr;
static long nif_tid;
static unsigned long nif_data;
static LIST_HEAD(header);
#ifdef __CONFIG_APP_DHCPV6__
static unsigned int if_flags = 0;
#endif

static int dispatch_event_cancel(void)
{
	long tid = nif_tid;
	if (tid) {
		nif_tid = 0;
		return itimer_cancel(tid, NULL);
	}
	return -1;
}

static int dispatch_event_defered(long id, unsigned long packed)
{
	dispatch_event((packed & 1) ? DF_WANBOUND : 0, DF_WANBOUND, ((packed >> 1) & 1));
	return 0;
}

struct rtgw {
	struct list_head list;
	struct in_addr gw;
	char oif[IFNAMSIZ];
};

static struct rtgw *rtgw_search(in_addr_t gw, const char *oif)
{
	struct rtgw *g;
	list_for_each_entry(g, &header, list)
		if ((gw == INADDR_ANY || g->gw.s_addr == gw) &&
		    (oif == NULL || !strcmp(g->oif, oif)))
			return g;
	return NULL;
}

static int rtgw_insert(in_addr_t gw, const char *oif)
{
	struct rtgw *g = rtgw_search(gw, oif);

	if (g == NULL) {
		g = (struct rtgw *)malloc(sizeof(*g));
		if (g == NULL)
			return -1;
		g->gw.s_addr = gw;
		strlcpy(g->oif, oif, IFNAMSIZ);
		list_add_tail(&g->list, &header);
	}
	return 0;
}

static int rtgw_delete(in_addr_t gw, const char *oif)
{
	struct rtgw *g = rtgw_search(gw, oif);
	if (g) {
		list_del(&g->list);
		free(g);
	}
	return (g) ? 0 : -1;
}

static inline void rtgw_flush(const char *oif)
{
	do {} while (!rtgw_delete(INADDR_ANY, oif));
}

static int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

static int rtgateway(struct rtmsg *r, struct nlmsghdr *n, const char *interface)
{
	struct rtattr *tb[RTA_MAX + 1];
	int len = n->nlmsg_len;
	char oif[64];

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

#ifndef NDEBUG
	print_route(r, n);
#endif
	if (r->rtm_family != AF_INET || r->rtm_dst_len)
		return -1;

	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
	if (tb[RTA_GATEWAY] && tb[RTA_OIF]) {
		if (!if_indextoname(*(int *)RTA_DATA(tb[RTA_OIF]), oif))
			return -1;
		if (n->nlmsg_type == RTM_DELROUTE)
			return rtgw_delete(*(in_addr_t *)RTA_DATA(tb[RTA_GATEWAY]), oif);
		else if (!strcmp(interface, oif)) {
			if (dispatch_event_cancel() != -1)
				dispatch_event_defered(0, nif_data);
			return rtgw_insert(*(in_addr_t *)RTA_DATA(tb[RTA_GATEWAY]), oif);
		}
	}

	return -1;
}

int rtnetaddress(const char *ifname, struct in_addr *in)
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

static void rtevent_post(struct nlmsghdr *nlh, const char *interface)
{
	int uncond = FALSE, good;
	struct in_addr ip = { .s_addr = 0 };

	rtnetaddress(interface, &ip);
	if ((good = (ip.s_addr && ip.s_addr != INADDR_NONE))) {
		if (nif_addr.s_addr != ip.s_addr) {
			uncond = TRUE;
			nif_addr = ip;
		}
	} else {
		rtgw_flush(interface);
		nif_addr.s_addr = 0;
	}

	dispatch_event_cancel();
	if (good && !rtgw_search(INADDR_ANY, interface)) {
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
		nif_data = (good | (uncond << 1));
		nif_tid = itimer_creat(nif_data, dispatch_event_defered, &tv);
	} else
		dispatch_event(good ? DF_WANBOUND : 0, DF_WANBOUND, uncond);
}

#ifdef __CONFIG_APP_DHCPV6__
#define IF_RA_OTHERCONF	0x80
#define IF_RA_MANAGED	0x40
#define IF_RA_RCVD	0x20
#define IF_RS_SENT	0x10

#define DHCP6C_PIDFILE	"/var/lib/dhcp6/dhcp6c.pid"

static int print_prefix(struct nlmsghdr *nlh)
{
	struct prefixmsg *prefix = NLMSG_DATA(nlh);
	int len = nlh->nlmsg_len;
	struct rtattr *rta;
	struct prefix_cacheinfo *pc;
	char tmp[64], buf[80] = { [0] = '\0' };

	len -= NLMSG_LENGTH(sizeof(*prefix));
	if (len < 0)
		return -1;

	for (rta = RTM_RTA(prefix); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if (rta->rta_type == PREFIX_ADDRESS)
			strlfcat(buf, sizeof(buf), "prefix %s/%d ",
				 inet_ntop(AF_INET6, RTA_DATA(rta), tmp, sizeof(tmp)),
				 prefix->prefix_len);
	}

	strlfcat(buf, sizeof(buf), "dev %s %s%s",
		 if_indextoname(prefix->prefix_ifindex, tmp),
		 (prefix->prefix_flags & IF_PREFIX_ONLINK) ? "onlink " : "",
		 (prefix->prefix_flags & IF_PREFIX_AUTOCONF) ? "autoconf " : "");

	for (rta = RTM_RTA(prefix); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		if (rta->rta_type == PREFIX_CACHEINFO) {
			pc = (struct prefix_cacheinfo *)RTA_DATA(rta);
			strlfcat(buf, sizeof(buf), "valid %u preferred %u",
				 pc->valid_time, pc->preferred_time);

		}
	}

	diag_printf("%s\n", buf);
	return 0;
}

static int in6_prefix(struct nlmsghdr *nlh, unsigned int *prevflg)
{
	struct prefixmsg *prefix = NLMSG_DATA(nlh);
	int client6_pid, timeout;

	if (prefix->prefix_family != AF_INET6)
		return -1;

	if (!nvram_get_int("x_ipv6_autoconfig_method", 0)) {
		client6_pid = fget_and_test_pid(DHCP6C_PIDFILE);

		if (prefix->prefix_pad2 & IF_RA_MANAGED) {
			if ((*prevflg & (IF_RA_OTHERCONF | IF_RA_MANAGED))
			    == IF_RA_OTHERCONF && client6_pid > 0)
				client6_pid = kill(client6_pid, SIGKILL);

			if (client6_pid <= 0)
				yexecl(NULL, "/var/lib/dhcp6/dhcp6c.script -6 br0 2");
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
					DIAG("wait for dhcp6c to exit (%d)\n", timeout);
					if (timeout <= 0)
						kill(client6_pid, SIGKILL);
				}
				client6_pid = 0;
			}

			if (client6_pid <= 0 && prefix->prefix_pad2 & IF_RA_OTHERCONF)
				yexecl(NULL, "/var/lib/dhcp6/dhcp6c.script -6 br0 0");
		}
	}

 	*prevflg = prefix->prefix_pad2;
	if (verbose)
		print_prefix(nlh);
	return 0;
}

static int dad_fail(struct nlmsghdr *nlh, struct ifaddrmsg *ifa)
{
	char tmp[32];
	int pid;

	if (nlh->nlmsg_type == RTM_NEWADDR &&
	    ifa->ifa_flags & IFA_F_DADFAILED &&
	    ifa->ifa_index == if_nametoindex("br0")) {
		syslog(LOG_WARNING, "%s: inet6 duplicate address dectected!",
		       if_indextoname(ifa->ifa_index, tmp));
		closelog();
		pid = fget_and_test_pid(DHCP6C_PIDFILE);
		if (pid > 0)
			kill(pid, SIGUSR1);
		return 0;
	}
	return -1;
}
#endif	/* __CONFIG_APP_DHCPV6__ */

#define netif_event_fdset select_event_fdset_dfl

static int netif_event_read(struct select_event_base *base, int fd)
{
	char buf[4096];
	struct sockaddr_nl remote;
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	struct ifinfomsg *imsg;
	socklen_t addrlen;
	int len, err;
	char nif[IFNAMSIZ];

	addrlen = sizeof(remote);
	len = recvfrom(fd, buf, sizeof(buf), 0,
	               (struct sockaddr *)&remote, &addrlen);

	if (len <= 0 || addrlen != sizeof(remote))
		return len;

	/* laborer won't be restarted by rc */
	strlcpy(nif, !nvram_get_int("OP_MODE", 0) ? "eth1" : "br0", sizeof(nif));

	err = len;
	for (nlh = (struct nlmsghdr *)buf;
	     NLMSG_OK(nlh, err); nlh = NLMSG_NEXT(nlh, err)) {
		switch (nlh->nlmsg_type) {
		case RTM_NEWLINK:
		case RTM_DELLINK:
			imsg = (struct ifinfomsg *)NLMSG_DATA(nlh);
			if (imsg->ifi_index != if_nametoindex(nif))
				break;
			if (imsg->ifi_flags & IFF_UP)
				rtevent_post(nlh, nif);
			else {
				rtgw_flush(nif);
				nif_addr.s_addr = 0;
				dispatch_event(0, DF_WANBOUND, 0);
			}
			break;
		case RTM_NEWADDR:
		case RTM_DELADDR:
			ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
#ifdef __CONFIG_APP_DHCPV6__
			if (ifa->ifa_family == AF_INET6)
				dad_fail(nlh, ifa);
			else
#endif
			if (ifa->ifa_index == if_nametoindex(nif))
				rtevent_post(nlh, nif);
			break;
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			rtgateway((struct rtmsg *)NLMSG_DATA(nlh), nlh, nif);
			break;
#ifdef __CONFIG_APP_DHCPV6__
		case RTM_NEWPREFIX:
			in6_prefix(nlh, &if_flags);
			break;
#endif
		default:
			break;
		}
	}
	return len;
}

static int netif_cli(int argc, char **argv, int fd)
{
	if (argc > 1) {
		if (!strcmp("route", argv[1])) {
			struct rtgw *g;
			list_for_each_entry(g, &header, list)
				dprintf(fd, "%s %s\n", inet_ntoa(g->gw), g->oif);
		} else if (!strcmp("verbose", argv[1])) {
			if (argc > 2)
				verbose = !!strtol(argv[2], NULL, 0);
		}
	}
	return 0;
}

static struct select_event_operation netif_event_op = {
	._fdset = netif_event_fdset,
	._read = netif_event_read,
};

static void __attribute__((constructor)) register_netif_event(void)
{
	int fd;
	struct sockaddr_nl addr;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd > -1) {
		bzero(&addr, sizeof(addr));
		addr.nl_family = AF_NETLINK;
		addr.nl_pid = getpid();
		addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_NOTIFY | RTMGRP_LINK | RTMGRP_IPV4_ROUTE;
#ifdef __CONFIG_APP_DHCPV6__
		addr.nl_groups |= RTMGRP_IPV6_PREFIX | RTMGRP_IPV6_IFADDR;
#endif

		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
			perror("bind");
		else if (!select_event_alloc(fd, &netif_event_op,
		                             NULL, "socket://netlink/ifaddress"))
			close(fd);
		else
			fifo_cmd_register("netif", NULL, NULL, netif_cli);
	} else
		perror(__func__);
}

#ifndef NDEBUG
static int rtnl_rttable_init;

struct rtnl_hash_entry {
	struct rtnl_hash_entry *next;
	char *			name;
	unsigned int		id;
};

static void
rtnl_hash_initialize(char *file, struct rtnl_hash_entry **hash, int size)
{
	struct rtnl_hash_entry *entry;
	char buf[512];
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp)
		return;
	while (fgets(buf, sizeof(buf), fp)) {
		char *p = buf;
		int id;
		char namebuf[64];

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == 0)
			continue;
		if (sscanf(p, "0x%x %63s\n", &id, namebuf) != 2 &&
		    sscanf(p, "0x%x %63s #", &id, namebuf) != 2 &&
		    sscanf(p, "%d %63s\n", &id, namebuf) != 2 &&
		    sscanf(p, "%d %63s #", &id, namebuf) != 2) {
			fprintf(stderr, "Database %s is corrupted at %s\n",
			        file, p);
			return;
		}

		if (id < 0)
			continue;
		entry = malloc(sizeof(*entry));
		entry->id   = id;
		entry->name = strdup(namebuf);
		entry->next = hash[id & (size - 1)];
		hash[id & (size - 1)] = entry;
	}
	fclose(fp);
}

static void rtnl_tab_initialize(char *file, char **tab, int size)
{
	char buf[512];
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp)
		return;
	while (fgets(buf, sizeof(buf), fp)) {
		char *p = buf;
		int id;
		char namebuf[64];

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == 0)
			continue;
		if (sscanf(p, "0x%x %63s\n", &id, namebuf) != 2 &&
		    sscanf(p, "0x%x %63s #", &id, namebuf) != 2 &&
		    sscanf(p, "%d %63s\n", &id, namebuf) != 2 &&
		    sscanf(p, "%d %63s #", &id, namebuf) != 2) {
			fprintf(stderr, "Database %s is corrupted at %s\n",
				file, p);
			return;
		}

		if (id < 0 || id > size)
			continue;

		tab[id] = strdup(namebuf);
	}
	fclose(fp);
}

static struct rtnl_hash_entry dflt_table_entry  = { .id = 253, .name = "default" };
static struct rtnl_hash_entry main_table_entry  = { .id = 254, .name = "main" };
static struct rtnl_hash_entry local_table_entry = { .id = 255, .name = "local" };

static struct rtnl_hash_entry * rtnl_rttable_hash[256] = {
	[253] = &dflt_table_entry,
	[254] = &main_table_entry,
	[255] = &local_table_entry,
};

static void rtnl_rttable_initialize(void)
{
	rtnl_rttable_init = 1;
	rtnl_hash_initialize("/etc/iproute2/rt_tables",
	                     rtnl_rttable_hash, 256);
}

static char * rtnl_rttable_n2a(__u32 id, char *buf, int len)
{
	struct rtnl_hash_entry *entry;

	if (id > RT_TABLE_MAX) {
		snprintf(buf, len, "%u", id);
		return buf;
	}
	if (!rtnl_rttable_init)
		rtnl_rttable_initialize();
	entry = rtnl_rttable_hash[id & 255];
	while (entry && entry->id != id)
		entry = entry->next;
	if (entry)
		return entry->name;
	snprintf(buf, len, "%u", id);
	return buf;
}

static char * rtnl_rtprot_tab[256] = {
	[RTPROT_UNSPEC] = "none",
	[RTPROT_REDIRECT] = "redirect",
	[RTPROT_KERNEL] = "kernel",
	[RTPROT_BOOT] = "boot",
	[RTPROT_STATIC] = "static",

	[RTPROT_GATED] = "gated",
	[RTPROT_RA] = "ra",
	[RTPROT_MRT] =	"mrt",
	[RTPROT_ZEBRA] = "zebra",
	[RTPROT_BIRD] = "bird",
	[RTPROT_DNROUTED] = "dnrouted",
	[RTPROT_XORP] = "xorp",
	[RTPROT_NTK] = "ntk",
	[RTPROT_DHCP] = "dhcp",
};

static int rtnl_rtprot_init;

static void rtnl_rtprot_initialize(void)
{
	rtnl_rtprot_init = 1;
	rtnl_tab_initialize("/etc/iproute2/rt_protos",
	                    rtnl_rtprot_tab, 256);
}

char * rtnl_rtprot_n2a(int id, char *buf, int len)
{
	if (id < 0 || id >= 256) {
		snprintf(buf, len, "%d", id);
		return buf;
	}
	if (!rtnl_rtprot_tab[id]) {
		if (!rtnl_rtprot_init)
			rtnl_rtprot_initialize();
	}
	if (rtnl_rtprot_tab[id])
		return rtnl_rtprot_tab[id];
	snprintf(buf, len, "%d", id);
	return buf;
}

static char * rtnl_rtscope_tab[256] = {
	"global",
};

static int rtnl_rtscope_init;

static void rtnl_rtscope_initialize(void)
{
	rtnl_rtscope_init = 1;
	rtnl_rtscope_tab[255] = "nowhere";
	rtnl_rtscope_tab[254] = "host";
	rtnl_rtscope_tab[253] = "link";
	rtnl_rtscope_tab[200] = "site";
	rtnl_tab_initialize("/etc/iproute2/rt_scopes",
	                    rtnl_rtscope_tab, 256);
}

char * rtnl_rtscope_n2a(int id, char *buf, int len)
{
	if (id < 0 || id >= 256) {
		snprintf(buf, len, "%d", id);
		return buf;
	}
	if (!rtnl_rtscope_tab[id]) {
		if (!rtnl_rtscope_init)
			rtnl_rtscope_initialize();
	}
	if (rtnl_rtscope_tab[id])
		return rtnl_rtscope_tab[id];
	snprintf(buf, len, "%d", id);
	return buf;
}

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
        __u32 table = r->rtm_table;
        if (tb[RTA_TABLE])
                table = *(__u32*) RTA_DATA(tb[RTA_TABLE]);
        return table;
}

static int print_route(struct rtmsg *r, struct nlmsghdr *n)
{
	struct rtattr *tb[RTA_MAX + 1];
	int len = n->nlmsg_len;
	char abuf[64];
	__u32 table;

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (r->rtm_family != AF_INET)
		return -1;
	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
	table = rtm_get_table(r, tb);

	if (n->nlmsg_type == RTM_DELROUTE)
		printf("Deleted ");

	if (tb[RTA_DST])
		printf("%s/%u ", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_DST]), abuf, sizeof(abuf)),
		       r->rtm_dst_len);
	else if (r->rtm_dst_len)
		printf("0/%d ", r->rtm_dst_len);
	else
		printf("default ");

	if (tb[RTA_SRC])
		printf("from %s/%u ", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_SRC]), abuf, sizeof(abuf)),
		        r->rtm_src_len);
	else if (r->rtm_src_len)
		printf("from 0/%u ", r->rtm_src_len);

	if (tb[RTA_GATEWAY])
		printf("via %s ", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_GATEWAY]), abuf, sizeof(abuf)));

	if (tb[RTA_OIF])
		printf("dev %s ", if_indextoname(*(int *)RTA_DATA(tb[RTA_OIF]), abuf) ? : "-");

	if (!(r->rtm_flags & RTM_F_CLONED)) {
		if (table != RT_TABLE_MAIN)
			printf(" table %s ", rtnl_rttable_n2a(table, abuf, sizeof(abuf)));
		if (r->rtm_protocol != RTPROT_BOOT)
			printf(" proto %s ", rtnl_rtprot_n2a(r->rtm_protocol, abuf, sizeof(abuf)));
		if (r->rtm_scope != RT_SCOPE_UNIVERSE)
			printf(" scope %s ", rtnl_rtscope_n2a(r->rtm_scope, abuf, sizeof(abuf)));
	}
	if (tb[RTA_PREFSRC])
		/* Do not use format_host(). It is our local addr
		   and symbolic name will not be useful.
		 */
		printf(" src %s ", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_PREFSRC]), abuf, sizeof(abuf)));

	if (tb[RTA_PRIORITY])
		printf(" metric %d ", *(__u32 *)RTA_DATA(tb[RTA_PRIORITY]));
	if (r->rtm_flags & RTNH_F_DEAD)
		printf("dead ");
	if (r->rtm_flags & RTNH_F_ONLINK)
		printf("onlink ");
	if (r->rtm_flags & RTNH_F_PERVASIVE)
		printf("pervasive ");
	if (r->rtm_flags & RTM_F_EQUALIZE)
		printf("equalize ");
	if (r->rtm_flags & RTM_F_NOTIFY)
		printf("notify ");
	putchar('\n');
	return 0;
}
#endif /* NDEBUG */

#ifdef DF_WANIPFILE
#include <libgen.h>
#include <sys/inotify.h>
#include "arping.h"

static int i_fd = -1;

#define wan_ip_fdset select_event_fdset_dfl

static int dispatch_wan_ip(const char *name)
{
	struct in_addr ip = { .s_addr = INADDR_ANY, };

	yfcat(name, "%hhu.%hhu.%hhu.%hhu", FIPQUAD(ip));
	return dispatch_event((ip.s_addr && ip.s_addr != -1U) ? DF_WANIPFILE : 0,
			DF_WANIPFILE, 0);
}

static int wan_ip_read(struct select_event_base *base, int fd)
{
#define BUF_LEN		(10 * (sizeof(struct inotify_event) + NAME_MAX + 1))
	char buf[BUF_LEN] __attribute__ ((aligned(4)));
	ssize_t len;
	char *p;
	struct inotify_event *i;

	len = read(fd, buf, BUF_LEN);
	if (len <= 0)
		return len;

	for (p = buf; p < (buf + len);) {
		i = (struct inotify_event *)p;
		if ((i->mask & (IN_CLOSE_WRITE|IN_ISDIR)) == IN_CLOSE_WRITE &&
		    i->len > 0 && !strcmp(i->name, strrchr(base->name, '/') + 1)) {
			dispatch_wan_ip(base->name);
			break;
		}
		p += (sizeof(*i) + i->len);
	}

	return len;
}

static int wan_ip_close(struct select_event_base *base, int fd)
{
	i_fd = -1;
	return 0;
}

static struct select_event_operation op = {
	._fdset = wan_ip_fdset,
	._read = wan_ip_read,
	._close = wan_ip_close,
};

static int mod_wan_ip(int argc, char **argv, int fd)
{
	int opt, ih, quit = 0;
	char *path, *path2, *dir, *file;
	struct select_event_base *base;

	optind = 0;	/* reset to 0, rather than the traditional value of 1 */
	while ((opt = getopt(argc, argv, "q")) != -1) {
		switch (opt) {
		case 'q':
			quit = 1;
			break;
		default:
			dprintf(fd, "Invalid option\n");
			return 1;
		}
	}

	if (quit) {
		if (i_fd > -1) {
			select_event_free(select_event_getbyfd(i_fd));
			i_fd = -1;
		}
	} else if (i_fd < 0 && optind < argc) {
		path = strdup(argv[optind]);
		dir = dirname(path);
		path2 = strdup(argv[optind]);
		file = basename(path2);
		if (dir[0] != '/' || file[0] == '/' || file[0] == '.')
			dprintf(fd, "Invalid path\n");
		else if ((ih = inotify_init()) != -1) {
			if (inotify_add_watch(ih, dir, IN_CLOSE_WRITE) < 0)
				dprintf(fd, "%s: %m\n", argv[optind]);
			else if ((base = select_event_alloc(ih, &op, NULL, "%s/%s", dir, file))) {
				i_fd = ih;
				dispatch_wan_ip(base->name);
			} else
				close(ih);
		}
		free(path);
		free(path2);
	}
	return (!quit);
}

static void __attribute__((constructor)) register_wan_ip_module(void)
{
	fifo_cmd_register("wan_ip",
		"\t[-q] <file>",
		"monitor wan ip file", mod_wan_ip);
}
#endif
