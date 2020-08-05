#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <sys/errno.h>
#include <sys/sysinfo.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/times.h>
#include <sys/mman.h>
#include <sys/klog.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <syslog.h>

#include "linux_list.h"
#include "auto_reboot.h"

#define IGNORE_IGMP1        0xefc03c03 //239.192.60.3
#define IGNORE_IGMP2		0xefc03c05 //239.192.60.5
#define IGNORE_IGMP3		0xefc03f64 //239.192.63.100
#define IGNORE_IGMP4		0xefc05007 //239.192.80.7

#define LOCAL_MCAST(x)  (((x) &0xFFFFFF00) == 0xE0000000)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct mcast_mbr {
	struct list_head list;
	struct in_addr address;
	uint8_t version;
	uint8_t port;
	uint16_t exclude;
};

struct mcast_group {
	struct list_head list;
	struct in_addr group;
	struct list_head mbrlist;
};

static int parse_line(char *line, char *argv[], int argvLen, const char *delim)
{
    char *q, *p = line;
    int i, argc = 0;

    while ((q = strsep(&p, delim))) {
        ydespaces(q);
        if (*q && (argc < argvLen))
            argv[argc++] = q;
    }
    for (i = argc; i < argvLen; i++)
        argv[i] = NULL;
    return argc;
}

static int mcast_group_add(struct list_head *head, uint32_t addr)
{
	struct mcast_group *gp;
	struct list_head *pos;

	list_for_each(pos, head) {
		gp = list_entry(pos, struct mcast_group, list);
		if (gp->group.s_addr == addr)
			return 0;
	}

	gp = (struct mcast_group *)malloc(sizeof(*gp));
	if (gp == NULL)
		return -1;

	gp->group.s_addr = addr;
	INIT_LIST_HEAD(&gp->mbrlist);
	list_add_tail(&gp->list, head);
	return 1;
}

static int if_readgroup(struct list_head *h, const char *ifname)
{
	FILE *f;
	char *argv[12];
	char buf[128];
	uint32_t addr;
	int num_group, count = 0;

	if ((f = fopen("/proc/net/igmp", "r")) == NULL)
		return 0;

	fgets(buf, sizeof(buf), f);
	while (fgets(buf, sizeof(buf), f)) {
		if (parse_line(buf, argv, 12, " \t\r\n") < 4)
			continue;
		if (strcmp(argv[1], ifname))
			continue;
		for (num_group = strtol(argv[3], NULL, 10);
		     num_group > 0 && fgets(buf, sizeof(buf), f) != NULL;
		     num_group--) {
			if (parse_line(buf, argv, 12, " \t\r\n") < 4)
				continue;
			/* reporter > 0 */
			if (strtol(argv[3], NULL, 10) > 0) {
				addr = strtoul(argv[0], NULL, 16);
				if (IN_MULTICAST(addr) &&
				    mcast_group_add(h, htonl(addr)) == 1) {
					count++;
				}
			}
		}
		break;
	}

	fclose(f);
	return count;
}

static int is_joined_to_if(struct list_head *h, uint32_t addr)
{
	struct list_head *pos;

	list_for_each(pos, h) {
		struct mcast_group *g = list_entry(pos, struct mcast_group, list);
		if (g->group.s_addr == addr)
			return 1;
	}

	return 0;
}


static struct mcast_mbr *
mcast_mbr_add(struct list_head *head, uint32_t group, uint32_t addr)
{
	struct mcast_group *g = NULL;
	struct mcast_mbr *m;
	struct list_head *pos, *pos2;

	list_for_each(pos, head) {
		g = list_entry(pos, struct mcast_group, list);
		if (g->group.s_addr == group) {
			list_for_each(pos2, &g->mbrlist) {
				m = list_entry(pos2, struct mcast_mbr, list);
				if (m->address.s_addr == addr)
					return m;
			}
			break;
		}
	}

	if (pos == head)
		return NULL;

	m = (struct mcast_mbr *)malloc(sizeof(*m));
	if (m != NULL) {
		m->address.s_addr = addr;
		list_add_tail(&m->list, &g->mbrlist);
	}
	return m;
}

static int read_mbr(FILE *f, uint32_t group, struct list_head *mc)
{
	int count = 0;
	char *argv[12], *p;
	char buf[128];
	struct mcast_mbr *mbr;

	while (fgets(buf, sizeof(buf), f)) {
		if (parse_line(buf, argv, 12, " (,:\\\r\n") != 7 ||
		    !(p = strchr(argv[0], '>')))
			break;
		mbr = mcast_mbr_add(mc, group, inet_addr(&p[1]));
		if (mbr != NULL) {
			mbr->port = atoi(argv[3])+1;
			mbr->version = argv[4][5] - '0';
			mbr->exclude = atoi(argv[6]);
			count += 1;
		}
	}
	return count;
}

static int read_group(FILE *f, struct list_head *mc)
{
	int count = 0;
	char *argv[12], *p;
	char buf[128];
	uint32_t addr;

	for (p = NULL; fgets(buf, sizeof(buf), f); )
		if (!strncmp(buf, "igmp list:", strlen("igmp list:"))) {
			p = buf;
			break;
		}

	if (p != NULL) {
		while (fgets(buf, sizeof(buf), f)) {
			if (parse_line(buf, argv, 12, " ,:\\\r\n") != 4 ||
			    strcmp("Group", argv[1]))
				break;
			addr = inet_addr(argv[3]);
			if (IN_MULTICAST(ntohl(addr)) &&
			    mcast_group_add(mc, addr) == 1) {
				read_mbr(f, addr, mc);
				count++;
			}
		}
	}
	return count;
}

static int read_mcast(struct list_head *mc, const char *path)
{
	FILE *f;
	char *argv[12];
	char buf[128];

	if ((f = fopen(path, "r")) == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), f)) {
		if (parse_line(buf, argv, 12, " ,:\\\r\n") > 7 &&
		    !strcmp(argv[0], "module") && !strcmp(argv[4], "eth*")) {
			read_group(f, mc);
		}
	}

	fclose(f);
	return 0;
}

static void mcast_group_free(struct list_head *head)
{
	while(!list_empty(head)) {
		struct mcast_group *g =
			list_entry(head->next, struct mcast_group, list);
		while (!list_empty(&g->mbrlist)) {
			struct mcast_mbr *m =
				list_entry(g->mbrlist.next, struct mcast_mbr, list);
			list_del(&m->list);
			free(m);
		}
		list_del(&g->list);
		free(g);
	}
}

int is_watching_tv_status()
{
	struct mcast_group *g;
	struct mcast_mbr *m;
	struct list_head *pos, *pos2;
	struct list_head mc;
	struct list_head upif_grp;
	uint32_t phyport, n, tmp;
	int count = 0;
	int opmode = -1;
	int is_watching_tv = 0;
	char c_time[80];
	time_t t;
	char *tmp_op;
	char group_mbr_port[5];

	INIT_LIST_HEAD(&mc);
	INIT_LIST_HEAD(&upif_grp);
	tmp_op = get_auto_reboot_config("op_mode");
	opmode= strtoul(tmp_op, NULL, 10);
	if (opmode == 0)
		if_readgroup(&upif_grp, "eth1");
	read_mcast(&mc, "/proc/rtl865x/igmp");
	t=time(NULL);
	strftime(c_time, sizeof(c_time), "%Y%m%d%H%M%S", localtime(&t));	//YYYYmmddHHMMSS
	n = 0;
	list_for_each(pos, &mc) {
		count = 0;
		g = list_entry(pos, struct mcast_group, list);
		tmp = ntohl(g->group.s_addr);
		// SSDP (Simple Service Discovery Protocol): 239.255.255.250
		// mDNS (Multicast DNS): 224.0.0.251
		// Local Peer Discovery: 239.192.152.143
		if (tmp == 0xeffffffa || tmp == 0xe00000fb || tmp == 0xefc0988f || LOCAL_MCAST(tmp))
			continue;
		if (!list_empty(&upif_grp) && !is_joined_to_if(&upif_grp, g->group.s_addr))
			continue;
		tmp = 0;
		memset(group_mbr_port, 0, sizeof(group_mbr_port));
		list_for_each(pos2, &g->mbrlist) {
			m = list_entry(pos2, struct mcast_mbr, list);
			if (m->port >= ARRAY_SIZE(group_mbr_port))
				continue;
			tmp |= (1 << m->port);
			group_mbr_port[m->port]++;
		}
		for ( phyport = 1; phyport < 5; phyport++) {
			if ( (tmp & (0x1 << phyport)) ) {
				if((g->group.s_addr != htonl(IGNORE_IGMP1)) && (g->group.s_addr != htonl(IGNORE_IGMP2)) &&
					(g->group.s_addr != htonl(IGNORE_IGMP3)) && (g->group.s_addr != htonl(IGNORE_IGMP4))) {
						is_watching_tv=1;
						break;
				}
			}
		}
	}
	mcast_group_free(&mc);
	return is_watching_tv;
}