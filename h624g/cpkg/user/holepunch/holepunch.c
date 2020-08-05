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
#include "holepunch.h"
#include "holepunch_misc.h"
#include "holepunch_vman.h"
#include <brdio.h>
#include <shutils.h>
#include <nmpipe.h>
#include <libytool.h>
#include <bcmnvram.h>
#include "custom.h"

#define WANIF "eth1"
#define LANIF "eth0"
/* ============= comes from rtl_nic.c ================*/
#define RTL819X_IOCTL_READ_PORT_STATS	              (SIOCDEVPRIVATE + 0x02)

struct port_statistics {
	unsigned int  rx_bytes;
	unsigned int  rx_unipkts;
	unsigned int  rx_mulpkts;
	unsigned int  rx_bropkts;
	unsigned int  rx_discard;
	unsigned int  rx_error;
	unsigned int  tx_bytes;
	unsigned int  tx_unipkts;
	unsigned int  tx_mulpkts;
	unsigned int  tx_bropkts;
	unsigned int  tx_discard;
	unsigned int  tx_error;
};
/* ====================================================*/

int g_run = 1;
int g_debug_flag;
int First_start=0;
struct _Hole_punch_info g_info;
static struct nmpipe *named_pipe = NULL;

struct _tmr {
	unsigned long exp;
	int enabled;
	int resp_seq;
} tmr[TMR_MAX];

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

struct _port_status pre_status[5];
struct _port_status now_status[5];
struct _wlan_status pre_wlan0_status[MAX_STATION_NUM * 5];
struct _wlan_status now_wlan0_status[MAX_STATION_NUM * 5];
struct _wlan_status pre_wlan1_status[MAX_STATION_NUM * 5];
struct _wlan_status now_wlan1_status[MAX_STATION_NUM * 5];

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

static int get_port_statistics(const char *interface, int port, struct port_statistics *stats)
{
	struct ifreq ifr;
	int s, rc;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	ifr.ifr_data = (void *)stats;
	*(int *)ifr.ifr_data = port;
	if ((rc = ioctl(s, RTL819X_IOCTL_READ_PORT_STATS, &ifr)))
		perror(__func__);
	close(s);
	return rc;
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

static long get_uptime(void)
{
	struct sysinfo info;
	sysinfo(&info);
	return info.uptime;
}

static void tmr_start(struct _tmr *tmr, int exp_sec)
{
	tmr->enabled = 1;
	tmr->exp = exp_sec*HZ + get_uptime();
}

static void tmr_stop(struct _tmr *tmr)
{
	tmr->enabled = 0;
	First_start = 0;
}

static int tmr_get_next_delta(unsigned long now)
{
	int i;
	int delta;
	int delta_min=0xffffff;

	for (i=0; i<TMR_MAX; i++) {
		if (!tmr[i].enabled)
			continue;
		delta = tmr[i].exp - now;
		if (delta < 0) {
			delta = (((unsigned long)0xffffffff) - now) + tmr[i].exp;
		}

		if (delta < delta_min) {
			delta_min = delta;
		}
	}

	if (delta_min < 0xffffff) {
		if (delta_min <= 0)
			delta_min = 1;
		return delta_min;
	} else {
		return HZ;
	}
}

static int tmr_expired(unsigned long now, struct _tmr *tmr)
{
	return (tmr && tmr->enabled && TIME_AFTER_EQ(now, tmr->exp));
}


static int read_int(const char *file, int def)
{
	FILE *f;
	int ret = def;

	if (!file || !file[0])
		return ret;

	f = fopen(file, "r");
	if (f) {
		if (fscanf(f, "%d", &ret) != 1)
			ret = def;
		fclose(f);
	}
	return ret;
}

static int read_ip(const char *path, in_addr_t *addr, char *s)
{
	FILE *f;
	char buffer[64];

	if (!path || !path[0])
		return 0;

	f = fopen(path, "r");
	if (f == NULL)
		return 0;

	buffer[0] = '\0';
	fgets(buffer, sizeof(buffer), f);
	fclose(f);
    	ydespaces(buffer);
    	if (!buffer[0])
		strcpy(buffer, "0.0.0.0");
    	*addr = inet_addr(buffer);
    	if (s)
		sprintf(s, "%u.%u.%u.%u", ((unsigned char *)addr)[0],
                                  			((unsigned char *)addr)[1],
                                  			((unsigned char *)addr)[2],
                                  			((unsigned char *)addr)[3]);
	return 1;
}

static int send_pkt(struct _Hole_punch_info *info, char *buf, int len, int server_id)
{
	struct sockaddr_in server;
	char buffer[32];
	char msg[4096];
	int n;

	if (info->sock_fd < 0)
		return 0;

	info->seq++;
	memset((void *)&msg, 0, sizeof(msg));
	n = snprintf(buffer, sizeof(buffer), "SEQ=%d\n", info->seq);
	memcpy((void *)&msg, buffer, n);
	memcpy((void *)&msg[n], buf, len);

	len = len + n;

	memset (&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	if (server_id==0) { 				// control server
		server.sin_addr.s_addr = info->control_server_ip;
		server.sin_port = info->control_server_port;
	} else { 						//report server
		server.sin_addr.s_addr = info->report_server_ip;
		server.sin_port = info->report_server_port;
	}

	if (sendto(info->sock_fd, msg, len, 0, (struct sockaddr *)&server, sizeof(server)) == len) {
		return 1;
	} else {
		return 0;
	}
}

static int get_wan_ip(long *addr, char *buf)
{
	return read_ip("/var/wan_ip", (in_addr_t *)addr, buf);
}

static int get_wan_netmask(long *addr, char *buf)
{
	return read_ip("/var/netmask", (in_addr_t *)addr, buf);
}

static int get_gateway(long *addr, char *buf)
{
	return read_ip("/var/gateway", (in_addr_t *)addr, buf);
}

static int check_wan_connect(void)
{
	char ip_str[32];
	long ip_long;

	/* WAN IP */
	if (get_wan_ip(&ip_long, ip_str) == 0)
		return 0;

	/* WAN Subnetmask */
	if (ip_long==0 || get_wan_netmask(&ip_long, ip_str) == 0)
		return 0;

	/* Gateway */
	if (ip_long==0 || get_gateway(&ip_long, ip_str) == 0)
		return 0;

	if (ip_long==0)
		return 0;

	return 1;
}

static void wait_connect_wan(void)
{
	while(!check_wan_connect()) {
		sleep(2);
	}
}

#if 0
/* APACRTL-540 */
static void get_control_server_info(struct _Hole_punch_info *info)
{
	char tmp[64];
	char *server;
	int port;

	server = holepunch_dv_get_value("dv_holepunch_control_server");
	if(server || server[0])
		sprintf(tmp, server);

	if ((info->control_server_ip = inet_addr(tmp))==INADDR_NONE) {
		struct hostent *host;
		if ((host=gethostbyname(tmp))!=NULL) {
			memcpy(&info->control_server_ip, (char *) host->h_addr_list[0], 4);
		}
	}

	port = safe_atoi(holepunch_dv_get_value("dv_holepunch_control_server_port"), 10219);
	info->control_server_port = htons(port);
}
#else
static void get_report_server_info(struct _Hole_punch_info *info)
{
	char tmp[64];
	char *server;
	int port;

	server = holepunch_dv_get_value("dv_holepunch_control_server");
	if(server || server[0])
		snprintf(tmp, sizeof(tmp), server);

	if ((info->report_server_ip = inet_addr(tmp))==INADDR_NONE) {
		struct hostent *host;
		if ((host=gethostbyname(tmp))!= NULL)
			memcpy(&info->report_server_ip, (char *) host->h_addr_list[0], 4);
	}

	port = safe_atoi(holepunch_dv_get_value("dv_holepunch_control_server_port"), 10219);
	info->report_server_port = htons(port);
}
#endif

static void init_ap_info(struct _Hole_punch_info *info)
{
	char model[64];
	char version[32];
	struct _AP_info *ap_info;
	char ip_str[32];
	long ip_long;

	yfcat("/etc/version", "%s", model);
	yfcat("/etc/version", "%*s %s", version);

	memset(info, 0, sizeof(struct _Hole_punch_info));

#if 0
/* APACRTL-540 */
	get_control_server_info(info);
#else
	get_report_server_info(info);
#endif
	info->seq = 0;
	info->sock_fd = -1;
	ap_info = &(info->ap_info);
	sprintf(ap_info->sysname, "%s", model);
	sprintf(ap_info->version, "%s", version);
	sprintf(ap_info->mac_wan, holepunch_nv_get_value("nv_wan_mac"));
	sprintf(ap_info->mac_wifi, holepunch_nv_get_value("nv_2.4G_mac"));
	sprintf(ap_info->mac_wifi_5g, holepunch_nv_get_value("nv_5G_mac"));
	if (get_wan_ip(&ip_long, ip_str) != 0)
		sprintf(ap_info->IP, "%s", ip_str);
}

static void dump_ap_info(struct _Hole_punch_info *info)
{
	struct _AP_info *ap_info;

	if(!g_debug_flag)
		return;

	printf ("\n==> AP info <==\n");
	ap_info = (struct _AP_info *)&(info->ap_info);
	printf ("sysname     : %s\n", ap_info->sysname);
	printf ("version     : %s\n", ap_info->version);
	printf ("MAC WAN     : %s\n", ap_info->mac_wan);
	printf ("MAC WIFI    : %s\n", ap_info->mac_wifi);
	printf ("MAC WIFI_5G    : %s\n", ap_info->mac_wifi_5g);
	printf ("IP          : %s\n", ap_info->IP);
	printf ("\n");

	printf ("==> Hole Punching Info <==\n");
#if 0
/* APACRTL-540 */
	printf ("Control Server IP   : %s\n", inet_ntoa(*(struct in_addr *)&info->control_server_ip));
	printf ("Control Server PORT : %u\n", ntohs(info->control_server_port));
#endif
	printf ("Report Server IP    : %s\n", inet_ntoa(*(struct in_addr *)&info->report_server_ip));
	printf ("Report Server PORT  : %u\n", ntohs(info->report_server_port));
	printf ("Seq                 : %d\n", info->seq);
	printf ("Sock fd             : %d\n", info->sock_fd);
	printf ("\n");

	printf ("=========================================\n");
}

static int open_socket(int *sockfd)
{
	int fd=-1, ret;
	struct sockaddr_in my;

	if (*sockfd == -1) {
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (fd < 0)
			return (-1);

		memset(&my, 0, sizeof(my));
		my.sin_family       = AF_INET;
		my.sin_addr.s_addr  = INADDR_ANY;
		my.sin_port         = htons(0);
		ret = bind(fd, (struct sockaddr *)&my, sizeof(my));
		if (ret < 0) {
			close(fd);
			return (-1);
		}
		*sockfd = fd;
	}

	return fd;
}

static int send_get_report_svr_info(struct _Hole_punch_info *info)
{
	char msg[1024];
	int n, len;
	struct _AP_info *ap_info;
	ap_info = &(info->ap_info);
	len = sizeof(msg);
	memset(msg, 0, sizeof(msg));

	tmr[TMR_REPORT].resp_seq = info->seq+1;

	n = 0;
	n += snprintf(&msg[n], len, "SYSNAME=%s\n", ap_info->sysname);
	n += snprintf(&msg[n], len-n, "VERSION=%s\n", ap_info->version);
	n += snprintf(&msg[n], len-n, "T=%s\n", "CMD");
	n += snprintf(&msg[n], len-n, "IP=%s\n", ap_info->IP);
	n += snprintf(&msg[n], len-n, "MAC_WAN=%s\n", ap_info->mac_wan);
	n += snprintf(&msg[n], len-n, "MAC_WIFI=%s\n", ap_info->mac_wifi);
	n += snprintf(&msg[n], len-n, "MAC_WIFI_5G=%s\n", ap_info->mac_wifi_5g);
	n += snprintf(&msg[n], len-n, "NEED_ACK=%d\n", 1);
	n += snprintf(&msg[n], len-n, "CMD=%s\n", get_cmd_str(CMD_GET_REPORT_SVR_INFO));
	return send_pkt(info, msg, n, 0);
}


static int connect_control_server(struct _Hole_punch_info *info)
{
	int ret;
	unsigned long next_poll = 0;
	unsigned long tmp;
	struct timeval tv;
	struct sockaddr_in fromAddr;
	unsigned int fromLen;
	int recvLen;
	fd_set  readfds, copy_reads;
	char msg[1024];
	struct _HolePunching_PKT hole_punching_pkt;

	info->seq = 0; //init sequence number

   	FD_ZERO(&readfds);
	FD_SET(info->sock_fd, &readfds);
	while (g_run) {
		if (info->sock_fd < 0) {
			g_run = 0;
			break;
		}
		if (next_poll==0) {
    		tv.tv_sec = 1;
	    	tv.tv_usec = 0;
        } else {
    		tv.tv_sec = safe_atoi(holepunch_dv_get_value("dv_holepunch_control_interval"), 60);
	    	tv.tv_usec = 0;
        }
		next_poll = get_uptime() + SEC2TICK(safe_atoi(holepunch_dv_get_value("dv_holepunch_control_interval"), 60));

again_connect_control:
        copy_reads = readfds;
		ret = select(info->sock_fd+1, &copy_reads, NULL, NULL, &tv);
		if (ret == 0) { //time out
		    if (send_get_report_svr_info(info)==0) {
// packet send error;
				return 0;
			}
		} else if (ret > 0) {
			int fd_set;
			char buffer[128];
			fd_set = FD_ISSET(info->sock_fd, &copy_reads);
			if (fd_set) {
				fromLen = sizeof(fromAddr);
				memset(msg, 0, sizeof(msg));
				recvLen = recvfrom(info->sock_fd, msg, sizeof(msg), 0,  (struct sockaddr *)&fromAddr, &fromLen);
				if (recvLen > 0) {
// check fromAddr, sequence number, data format
					char *value, *name;
					char *fmem;
					key_variable *v;

                	if ((fromAddr.sin_addr.s_addr == info->control_server_ip) && (fromAddr.sin_port == info->control_server_port)) {

						fmem = msg;
						memset(&hole_punching_pkt, 0, sizeof(struct _HolePunching_PKT));
						while ( (fmem = read_lines(fmem, buffer, sizeof(buffer))) ) {
							value = buffer;
							name = strsep(&value, "=");
							ydespaces(value);
							ydespaces(name);
							if (!name)
								continue;
							if (!value)
								continue;
                            for (v=get_key_tbl(); v->name; v++) {
								if (!strcmp(v->name, name)) {
									hole_punching_pkt_set(v->id, (void *)value, &hole_punching_pkt);
								}
							}
						}
						if ( (hole_punching_pkt.resp_seq==info->seq) && \
									(hole_punching_pkt.cmd_type==CMD_TYPE_ID_ACK) && \
									( hole_punching_pkt.cmd==CMD_GET_REPORT_SVR_INFO) ){
							char *ip, *port;
							in_addr_t addr;

							port = hole_punching_pkt.result;
							ip = strsep(&port, ":");
							ydespaces(port);
							ydespaces(ip);
							if (port) {
								addr = inet_addr(ip);
								if ( (atoi(port)>0) && (ntohl(addr)>0)) {
									info->report_server_ip = addr;
									info->report_server_port = htons(atoi(port));
									return 1;
								}
							}
						}
					}
				}
			}
			tmp = next_poll - get_uptime();
			if (tmp > 0) {
				tv.tv_sec = TICK2SEC(tmp);
				tv.tv_usec = 0;
			} else {
				tv.tv_sec = 0;
				tv.tv_usec = 10*1000;
			}
			if (g_run)
				goto again_connect_control;
		}
	}
	return 0;
}

static void sig_handler(int signo)
{
	switch(signo) {
		case SIGTERM:
			g_run = 0;
			unlink(HOLEPUNCH_PID_FILE);
			exit(-1);
			break;
	}
}

static int test_pid(const char *pid_file)
{
	char path[64];
	int pid = read_pid(pid_file);

    	if (pid <= 0)
 		return 0;

    	sprintf(path, "/proc/%d/cmdline", pid);
	return (access(path, F_OK) == 0) ? pid : 0;
}

static int write_pid(const char *pid_file)
{
	FILE *f;
	int pid = 0;

	if (!pid_file || !pid_file[0])
        return 0;

	if ((f = fopen(pid_file, "w"))) {
		pid = getpid();
		fprintf(f, "%d\n", pid);
		fclose(f);
    	}

	return pid;
}

static void send_holepunching_keep_live(struct _Hole_punch_info *info)
{
	char msg[1024];
	int n, len;
	struct _AP_info *ap_info;
	char ip_str[32];
	long ip_long;
	ap_info = &(info->ap_info);
	len = sizeof(msg);

	if (get_wan_ip(&ip_long, ip_str) == 0)
		sprintf(ip_str, "%s", ap_info->IP);

	memset(msg, 0, sizeof(msg));

	n = 0;
	n += snprintf(&msg[n], len, "SYSNAME=%s\n", ap_info->sysname);
	n += snprintf(&msg[n], len-n, "VERSION=%s\n", ap_info->version);
	n += snprintf(&msg[n], len-n, "T=%s\n", get_cmd_type_str(CMD_TYPE_ID_KEEP_ALIVE));
	n += snprintf(&msg[n], len-n, "MAC_WAN=%s\n", ap_info->mac_wan);
	n += snprintf(&msg[n], len-n, "MAC_WIFI=%s\n", ap_info->mac_wifi);
	n += snprintf(&msg[n], len-n, "MAC_WIFI_5G=%s\n", ap_info->mac_wifi_5g);
	n += snprintf(&msg[n], len-n, "IP=%s\n", ip_str);
	n += snprintf(&msg[n], len-n, "NEED_ACK=%d\n", 0);
	send_pkt(info, msg, n, 1);
}

static void get_byte_counts(struct _port_status *status)
{
    FILE *fp;
    char *tmp, *value;
    char buffer[512];
    int i;

    if((fp=fopen("/proc/asicCounter","r"))!=NULL) {
        i = 0;
        while(fgets(buffer, 512, fp)) {
            if(i >= 2 && i <= 6) {
                value = buffer;
                tmp = strsep(&value, ":");
                ydespaces(value);
                tmp = strsep(&value, " ");
                status[i-2].inputOCT = strtoull(tmp, NULL, 10);
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                status[i-2].CRC = strtoul(tmp, NULL, 10);
                ydespaces(value);
            }

            if (i >= 11 && i <= 15) {
                value = buffer;
                tmp = strsep(&value, ":");
                ydespaces(value);
                tmp = strsep(&value, " ");
                status[i-11].outputOCT = strtoull(tmp, NULL, 10);
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
            }
            i++;
        }
        fclose(fp);
    }
}

static void send_port_status_report(struct _Hole_punch_info *info)
{
	int i;
	char msg[1024];
	char inputOctect[5][12], outputOctect[5][12], crc[5][12], now[5][32];
	int n, len;
	struct _port_status status[5];
	unsigned int phy_status[5];

	time_t t;
	len = sizeof(msg);

	get_byte_counts(status);
	for(i=0; i<5; i++) {
		phy_status[i]=switch_port_status(i);
		if (phy_status[i] & PHF_LINKUP){
			sprintf(inputOctect[i], "%llu", status[i].inputOCT);
			sprintf(outputOctect[i], "%llu", status[i].outputOCT);
			sprintf(crc[i], "%lu", status[i].CRC);
			t=time(NULL);
			strftime(now[i], 32, "%Y%m%d%H%M%S", localtime(&t));	//YYYYmmddHHMMSS
		} else {
			strcpy(inputOctect[i], "");
			strcpy(outputOctect[i], "");
			strcpy(crc[i], "");
			strcpy(now[i], "");
		}
	}

	n = 0;
	n += snprintf(&msg[n], len-n, "T=%s\n", get_cmd_type_str(CMD_TYPE_ID_ACK));
	n += snprintf(&msg[n], len-n, "CMD=SEND-PORT-STATUS-REPORT\n");
	n += snprintf(&msg[n], len-n, "RESULT=");
	n += snprintf(&msg[n], len-n, "1|0|WAN|%s|%s|%s|%s,",inputOctect[4], outputOctect[4], crc[4], now[4]);
	n += snprintf(&msg[n], len-n, "2|1|LAN1|%s|%s|%s|%s,",inputOctect[0], outputOctect[0], crc[0], now[0]);
	n += snprintf(&msg[n], len-n, "3|2|LAN2|%s|%s|%s|%s,",inputOctect[1], outputOctect[1], crc[1], now[1]);
	n += snprintf(&msg[n], len-n, "4|3|LAN3|%s|%s|%s|%s,",inputOctect[2], outputOctect[2], crc[2], now[2]);
	n += snprintf(&msg[n], len-n, "5|4|LAN4|%s|%s|%s|%s\n",inputOctect[3], outputOctect[3], crc[3], now[3]);

	send_pkt(info, msg, n, 1);
}

static void send_igmp_join_table_report(struct _Hole_punch_info *info)
{
	struct mcast_group *g;
	struct mcast_mbr *m;
	struct list_head *pos, *pos2;
	struct list_head mc;
	struct list_head upif_grp;
	uint32_t phyport, len, tmp;
	int n = 0;
	char c_time[80];
	time_t t;
	char msg[1024];
	char *tmp_op;
	char group_mbr_port[5];
	int opmode = -1;
	int i = 0;

	len = sizeof(msg);
	n += snprintf(&msg[n], len-n, "T=%s\n", get_cmd_type_str(CMD_TYPE_ID_ACK));
	n += snprintf(&msg[n], len-n, "CMD=SEND-IGMP-JOIN-TABLE-REPORT\n");
	n += snprintf(&msg[n], len-n, "RESULT=");

	INIT_LIST_HEAD(&mc);
	INIT_LIST_HEAD(&upif_grp);
	tmp_op = holepunch_nv_get_value("nv_opmode");
	opmode= strtoul(tmp_op, NULL, 10);
	if (opmode == 0)
		if_readgroup(&upif_grp, "eth1");
	read_mcast(&mc, "/proc/rtl865x/igmp");

	t=time(NULL);
	strftime(c_time, sizeof(c_time), "%Y%m%d%H%M%S", localtime(&t));	//YYYYmmddHHMMSS
	list_for_each(pos, &mc) {
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
				n += snprintf(&msg[n], len-n, "%s%d|%s:|%d|%d|%s",
					(i==0)?"":",", i+1, inet_ntoa(g->group), group_mbr_port[phyport], phyport, c_time);
				i++;
			}
		}
	}
	msg[n]='\n';
	n=n+1;
	send_pkt(info, msg, n, 1);
	mcast_group_free(&mc);

}

static int memory_used(void)
{
	char buf[256], tmp[256];
	unsigned long total, mfree;
	FILE *fp;

	total = mfree = 0;
	fp = fopen("/proc/meminfo", "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			if (strstr(buf, "MemTotal:")!=NULL)
				sscanf(buf, "%s %lu kB", tmp, &total);
			else if (strstr(buf, "MemFree:")!=NULL)
				sscanf(buf, "%s %lu kB", tmp, &mfree);
		}
		fclose(fp);
		if (total!=0 && mfree!=0)
			return 100 - ((mfree*100) / total );
		else
			return 0;

	}
	return 0;
}

static void send_resource_status_report(struct _Hole_punch_info *info)
{
	int n, len;
	char now[32], buf[512];
	time_t t;
	double cpu_idle_load=0, cpu_usage=0;
	int ram_utilization;
	unsigned long total_fla, used_fla, flash_mem_utilization;
	char msg[1024];

	len = sizeof(msg);
	t=time(NULL);
	strftime(now, 32, "%Y%m%d%H%M%S", localtime(&t));	//YYYYmmddHHMMSS

	named_pipe = prequest("cpu_stat");
	if (named_pipe) {
    	if (presponse(named_pipe, buf, sizeof(buf)) > 0)
        	sscanf(buf, "%lf", &cpu_idle_load);
		prelease(named_pipe);
		cpu_usage = 100 - cpu_idle_load;
	}

	if ((int)cpu_usage < 1)
		cpu_usage = 1;

	ram_utilization = memory_used();
	/*boot+cfg+linux + root_fs + b_nvram + nvram = 0x1f00000 SPI flash(GD25Q128) was found at CS0, size 0x2000000 */
	total_fla=0x2000000;
	used_fla=0x1f00000;
	flash_mem_utilization =(used_fla*100)/total_fla;

	n=0;
	n += snprintf(&msg[n], len-n, "T=%s\n", get_cmd_type_str(CMD_TYPE_ID_ACK));
	n += snprintf(&msg[n], len-n, "CMD=SEND-RESOURCE-REPORT\n");
	n += snprintf(&msg[n], len-n, "RESULT=");
	n += snprintf(&msg[n], len-n, "%d|%d|%lu|%s\n", (int)cpu_usage, ram_utilization, flash_mem_utilization, now);

	send_pkt(info, msg, n, 1);
}

static void reboot()
{
	system("killall -TERM igmpproxy 2>/dev/null"); //give change to send igmp leave
	system("killall -USR2 udhcpc 2>/dev/null");
	system("killall -TERM snmp 2>/dev/null");
	syslog(LOG_INFO, "system reboot in holepunch");
	usleep(1000 * 1000); // 1 sec
	yexecl(NULL, "reboot");
}

static char *status_reverse(char *status)
{
	int val;

	val=atoi(status);
	if(val==0)
		strcpy(status, "1");
	else
		strcpy(status, "0");

	return status;
}

static void get_wifi_status(struct _HolePunching_PKT *pkt)
{
	char tmp[4], buf[20];
	char *args, *freq;

	strcpy(buf, pkt->args);
	args=buf;
	ydespaces(args);

	if (strlen(args) < 1) {
		strcpy(pkt->result, "-1");
	} else {
		if (!(strncmp(args, "FREQ=", strlen("FREQ=")))) {
			freq = strsep(&args, "=");
			ydespaces(args);
			if(strcmp(args,"2.4G")==0) {
				snprintf(tmp, sizeof(tmp), holepunch_nv_get_value("nv_2.4G_disabled"));
				snprintf(pkt->result, sizeof(pkt->result), "FREQ=%s,STATUS=%s", args, status_reverse(tmp));
			} else if(strcmp(args,"5G")==0) {
				snprintf(tmp, sizeof(tmp), holepunch_nv_get_value("nv_5G_disabled"));
				snprintf(pkt->result, sizeof(pkt->result), "FREQ=%s,STATUS=%s", args, status_reverse(tmp));
			} else
				strcpy(pkt->result, "-1");
		} else
			strcpy(pkt->result, "-1");
	}
}

static void set_wifi_status(struct _HolePunching_PKT *pkt)
{
	char buf[50];
	char *args, *freq, *enable;
	char *tmp;

	strcpy(buf, pkt->args);
	args = buf;
	tmp = strsep(&args, "=");
	ydespaces(tmp);

	if (strcmp(tmp, "FREQ")) {
		strcpy(pkt->result, "-1");
		return;
	}

	freq = strsep(&args, ",");
	ydespaces(freq);
	if (strcmp(freq,"2.4G") != 0 && strcmp(freq,"5G") != 0) {
		strcpy(pkt->result, "-1");
		return;
	}

	enable = strsep(&args, "=");

	if(!enable || !enable[0] || !strlen(enable)) {
		strcpy(pkt->result, "-1");
		return;
	}

	if (strcmp(enable, "ENABLE")) {
		strcpy(pkt->result, "-1");
		return;
	}

	if ( strcmp(args, "1") && strcmp(args, "0") ) {
		strcpy(pkt->result, "-1");
		return;
	}

	if(strcmp(freq, "2.4G") == 0) {
		holepunch_nv_set_value(wlan1_disable, status_reverse(args));
		tmp = holepunch_nv_get_value("nv_2.4G_disabled");
	} else {
		holepunch_nv_set_value(wlan0_disable, status_reverse(args));
		tmp = holepunch_nv_get_value("nv_5G_disabled");
	}

	snprintf(pkt->result, sizeof(pkt->result), "FREQ=%s,STATUS=%s", freq, status_reverse(tmp));
}

static void get_ssid_status(struct _HolePunching_PKT *pkt)
{
	char status[4], buf[52] = {0,};
	char ssid[64] = {0,};
	char *args, *freq, *tmp;
	int n, len;

	len = sizeof(pkt->result);
	strcpy(buf, pkt->args);
	args = buf;
	ydespaces(args);

	if (strlen(args) == 0) {
		freq = "2.4G";
	} else if (!(strncmp(args, "FREQ=", strlen("FREQ=")))) {
		tmp = strsep(&args, "=");
		ydespaces(args);
		freq = args;
	} else {
		strcpy(pkt->result, "-1");
		return;
	}

	n = 0;
	if (strcmp(freq, "2.4G") == 0) {
		n += snprintf(&pkt->result[n], len, "FREQ=%s,", freq);
		sprintf(status, holepunch_nv_get_value("nv_2.4G_disabled"));							//SK_WiFiXXXX
		snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_ssid"));
		n += snprintf(&pkt->result[n], len, "[1]%s=%s,", ssid, status_reverse(status));
		if (strcmp(status, "0") == 0) {
			snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_void_ssid"));	//SK_VoIP
			n += snprintf(&pkt->result[n], len-n, "[2]%s=%s,", ssid, "0");
			snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_t_wifi_ssid"));	//T wifi home
			n += snprintf(&pkt->result[n], len-n, "[3]%s=%s,", ssid, "0");
			snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_multi_ssid"));	//SK_WiFiXXXX_2.4
			n += snprintf(&pkt->result[n], len-n, "[5]%s=%s", ssid, "0");
		} else {
			sprintf(status, holepunch_nv_get_value("nv_2.4G_voip_disabled"));					//SK_VoIP
			snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_void_ssid"));
			n += snprintf(&pkt->result[n], len-n, "[2]%s=%s,", ssid, status_reverse(status));
			sprintf(status, holepunch_nv_get_value("nv_2.4G_t_wifi_disabled"));					//T wifi home
			snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_t_wifi_ssid"));
			n += snprintf(&pkt->result[n], len-n, "[3]%s=%s,", ssid, status_reverse(status));
			sprintf(status, holepunch_nv_get_value("nv_2.4G_multi_disabled"));					//SK_WiFiXXXX_2.4
			snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_multi_ssid"));
			n += snprintf(&pkt->result[n], len-n, "[5]%s=%s", ssid, status_reverse(status));
		}
	} else if (strcmp(args, "5G") == 0) {
		n += snprintf(&pkt->result[n], len, "FREQ=%s,", freq);
		sprintf(status, holepunch_nv_get_value("nv_5G_disabled"));				//SK_WiFiXXXX_5G
		snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_5G_ssid"));
		n += snprintf(&pkt->result[n], len, "[1]%s=%s", ssid, status_reverse(status));
	} else
		strcpy(pkt->result, "-1");
}

static void set_ssid_status(struct _HolePunching_PKT *pkt)
{
	char status[4], buf[52] = {0,}, param[64] = {0,};
	char *args, *freq, *tmp;
	char *ssid, *idx;
	char *ssid_1, *ssid_2, *ssid_3, *ssid_4;		//1:SK_WiFiXXXX		2:SK_VoIP		3:T wifi home	4:SK_WiFiXXXX_2.4
	int n, len, status_len, ssid_idx;

	len = sizeof(pkt->result);
	strcpy(buf, pkt->args);
	args = buf;
	tmp = strsep(&args, "=");
	ydespaces(tmp);

	if (strcmp(tmp, "FREQ") == 0) {
		freq = strsep(&args, ",");
		ydespaces(freq);
		if (strcmp(freq,"2.4G") != 0 && strcmp(freq,"5G") != 0) {
			strcpy(pkt->result, "-1");
			return;
		}
		ydespaces(args);
		tmp = strsep(&args, "=");
		ydespaces(tmp);
		if(tmp == NULL) {
			strcpy(pkt->result, "-1");
			return;
		} else if ((strcmp(tmp, "SSID-NAME") != 0) && (strcmp(tmp, "SSID_IDX") != 0)) {
			strcpy(pkt->result, "-1");
			return;
		}
		ydespaces(args);
	} else {
		strcpy(pkt->result, "-1");
		return;
	}

	if(args == NULL) {
		strcpy(pkt->result, "-1");
		return;
	}

	status_len = strlen(args);
	if(status_len == 0) {
		strcpy(pkt->result, "-1");
		return;
	}

	if (strcmp(tmp, "SSID-NAME") == 0) {
		ssid = strsep(&args, ",");
		if (strcmp(freq, "5G") == 0) {
			ssid_1 = holepunch_nv_get_value("nv_5G_ssid");			//1:SK_WiFiXXXX
			if (strcmp(ssid, ssid_1)) {
				strcpy(pkt->result, "-1");
				return;
			}
		} else {
			ssid_1 = holepunch_nv_get_value("nv_2.4G_ssid");		//1:SK_WiFiXXXX
			ssid_2 = holepunch_nv_get_value("nv_2.4G_void_ssid");	//2:SK_VoIP
			ssid_3 = holepunch_nv_get_value("nv_2.4G_t_wifi_ssid");	//3:T wifi home
			ssid_4 = holepunch_nv_get_value("nv_2.4G_multi_ssid");	//5:SK_WiFiXXXX_2.4
			if (strcmp(ssid, ssid_1) && strcmp(ssid, ssid_2) && strcmp(ssid, ssid_3) && strcmp(ssid, ssid_4)) {
				strcpy(pkt->result, "-1");
				return;
			}
		}

		tmp = strsep(&args, "=");

		if (strcmp(tmp, "STATUS")) {
			strcpy(pkt->result, "-1");
			return;
		}

		ydespaces(args);

		if(args == NULL) {
			strcpy(pkt->result, "-1");
			return;
		}

		status_len = strlen(args);
		if(status_len == 0) {
			strcpy(pkt->result, "-1");
			return;
		}

		if (strcmp(args, "0") && strcmp(args, "1")) {
			strcpy(pkt->result, "-1");
			return;
		}

		n = 0;
		n += snprintf(&pkt->result[n], len, "FREQ=%s,", freq);

		if ((strcmp(freq, "5G") == 0)) {											// 5g
			if (strcmp(ssid, ssid_1) == 0) {										//1:SK_WiFiXXXX
				snprintf(param, sizeof(param), "nv_%s_disabled", freq);
				holepunch_nv_set_value(wlan0_disable, status_reverse(args));
				n += snprintf(&pkt->result[n], len, "SSID=[1]%s,", ssid);
			}
		} else {																	// 2g
			if (strcmp(ssid, ssid_1) == 0) {
				snprintf(param, sizeof(param), "nv_%s_disabled", freq);				//1:SK_WiFiXXXX
				holepunch_nv_set_value(wlan1_disable, status_reverse(args));
				n += snprintf(&pkt->result[n], len, "SSID=[1]%s,", ssid);
			} else if (strcmp(ssid, ssid_2) == 0) {
				snprintf(param, sizeof(param), "nv_%s_voip_disabled", freq);		//2:SK_VoIP
				holepunch_nv_set_value(wlan1_voip_disable, status_reverse(args));
				n += snprintf(&pkt->result[n], len, "SSID=[2]%s,", ssid);
			} else if (strcmp(ssid, ssid_3) == 0) {
				snprintf(param, sizeof(param), "nv_%s_t_wifi_disabled", freq);		//3:T wifi home
				holepunch_nv_set_value(wlan1_t_wifi_disable, status_reverse(args));
				n += snprintf(&pkt->result[n], len, "SSID=[3]%s,", ssid);
			} else {
				snprintf(param, sizeof(param), "nv_%s_multi_disabled", freq);		//5:SK_WiFiXXXX_2.4
				holepunch_nv_set_value(wlan1_multi_disable, status_reverse(args));
				n += snprintf(&pkt->result[n], len, "SSID=[5]%s,", ssid);
			}
		}
	} else {
		idx = strsep(&args, ",");
		ssid_idx = strtol(idx, NULL, 10);
		if (ssid_idx < 1 || ssid_idx > 5) {
			strcpy(pkt->result, "-1");
			return;
		}

		if (strcmp(freq, "5G") == 0) {		// 5g
			if (ssid_idx != 1) {
				strcpy(pkt->result, "-1");
				return;
			}
		} else {							// 2.4g
			if (ssid_idx == 4) {
				strcpy(pkt->result, "-1");
				return;
			}
		}

		tmp = strsep(&args, "=");

		if (strcmp(tmp, "STATUS")) {
			strcpy(pkt->result, "-1");
			return;
		}

		ydespaces(args);

		if(args == NULL) {
			strcpy(pkt->result, "-1");
			return;
		}

		status_len = strlen(args);
		if(status_len == 0) {
			strcpy(pkt->result, "-1");
			return;
		}

		if (strcmp(args, "0") && strcmp(args, "1")) {
			strcpy(pkt->result, "-1");
			return;
		}

		n = 0;
		n += snprintf(&pkt->result[n], len, "FREQ=%s,", freq);
		if (strcmp(freq, "5G") == 0) {											// 5g
			if (ssid_idx == 1) {
				snprintf(param, sizeof(param), "nv_%s_ssid", freq);				//1:SK_WiFiXXXX
				ssid = holepunch_nv_get_value(param);
				snprintf(param, sizeof(param), "nv_%s_disabled", freq);
				holepunch_nv_set_value(wlan0_disable, status_reverse(args));
				n += snprintf(&pkt->result[n], len, "SSID=[1]%s,", ssid);
			}
		} else {
			if (ssid_idx == 1) {												// 2.4g
				snprintf(param, sizeof(param), "nv_%s_ssid", freq);				//1:SK_WiFiXXXX
				ssid = holepunch_nv_get_value(param);
				snprintf(param, sizeof(param), "nv_%s_disabled", freq);
				holepunch_nv_set_value(wlan1_disable, status_reverse(args));
				n += snprintf(&pkt->result[n], len, "SSID=[1]%s,", ssid);
			} else if (ssid_idx == 2) {
				snprintf(param, sizeof(param), "nv_%s_void_ssid", freq);		//2:SK_VoIP
				ssid = holepunch_nv_get_value(param);
				snprintf(param, sizeof(param), "nv_%s_voip_disabled", freq);
				holepunch_nv_set_value(wlan1_voip_disable, status_reverse(args));
				n += snprintf(&pkt->result[n], len, "SSID=[2]%s,", ssid);
			} else if (ssid_idx == 3) {
				snprintf(param, sizeof(param), "nv_%s_t_wifi_ssid", freq);		//3:T wifi home
				ssid = holepunch_nv_get_value(param);
				snprintf(param, sizeof(param), "nv_%s_t_wifi_disabled", freq);
				holepunch_nv_set_value(wlan1_t_wifi_disable, status_reverse(args));
				n += snprintf(&pkt->result[n], len, "SSID=[3]%s,", ssid);
			} else {
				snprintf(param, sizeof(param), "nv_%s_multi_ssid", freq);		//4:SK_WiFiXXXX_2.4
				ssid = holepunch_nv_get_value(param);
				snprintf(param, sizeof(param), "nv_%s_multi_disabled", freq);
				holepunch_nv_set_value(wlan1_multi_disable, status_reverse(args));
				n += snprintf(&pkt->result[n], len, "SSID=[5]%s,", ssid);
			}
		}
	}

	snprintf(status, sizeof(status), holepunch_nv_get_value(param));
	n += snprintf(&pkt->result[n], len, "STATUS=%s", status_reverse(status));
}

static void get_ssid_rate(struct _HolePunching_PKT *pkt)
{
	char rate[12], buf[52], ssid[64];
	char *args, *freq, *tmp;
	char *tmp_rate;
	int n, len;

	len = sizeof(pkt->result);

	strcpy(buf, pkt->args);
	args = buf;
	ydespaces(args);
	if (strlen(args) == 0) {
		freq="2.4G";
	} else if(!(strncmp(args, "FREQ=", strlen("FREQ=")))) {
		tmp = strsep(&args, "=");
		ydespaces(args);
		freq = args;
	} else {
		strcpy(pkt->result, "-1");
		return;
	}

	n = 0;
	if (strcmp(freq,"2.4G") == 0) {
		n += snprintf(&pkt->result[n], len, "FREQ=%s,", freq);
		tmp_rate = holepunch_nv_get_value("nv_2.4G_main_ratelimit");
		if(!tmp_rate)
			sprintf(rate, "0");
		else
			sprintf(rate, tmp_rate);
		snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_ssid"));
		n += snprintf(&pkt->result[n], len, "[1]%s=%s,", ssid, rate);
		tmp_rate = holepunch_nv_get_value("nv_2.4G_voip_ratelimit");
		if(!tmp_rate)
			sprintf(rate, "0");
		else
			sprintf(rate, tmp_rate);
		snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_void_ssid"));
		n += snprintf(&pkt->result[n], len-n, "[2]%s=%s,", ssid, rate);
		tmp_rate = holepunch_nv_get_value("nv_2.4G_t_wifi_ratelimit");
		if(!tmp_rate)
			sprintf(rate, "0");
		else
			sprintf(rate, tmp_rate);
		snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_t_wifi_ssid"));
		n += snprintf(&pkt->result[n], len-n, "[3]%s=%s,", ssid, rate);
		tmp_rate = holepunch_nv_get_value("nv_2.4G_multi_ratelimit");
		if(!tmp_rate)
			sprintf(rate, "0");
		else
			sprintf(rate, tmp_rate);
		snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_2.4G_multi_ssid"));
		n += snprintf(&pkt->result[n], len-n, "[5]%s=%s", ssid, rate);
	} else if(strcmp(freq, "5G") == 0) {
		n += snprintf(&pkt->result[n], len, "FREQ=%s,", freq);
		tmp_rate = holepunch_nv_get_value("nv_5G_main_ratelimit");
		if(!tmp_rate)
			sprintf(rate, "0");
		else
			sprintf(rate, tmp_rate);
		snprintf(ssid, sizeof(ssid), "%s", holepunch_nv_get_value("nv_5G_ssid"));
		n += snprintf(&pkt->result[n], len, "[1]%s=%s", ssid, rate);
	} else
		strcpy(pkt->result, "-1");
}

static void set_ssid_rate(struct _HolePunching_PKT *pkt)
{
	char rate[12]={'\0'}, buf[52], param[64];
	char *args, *freq, *tmp;
	char *ssid, *idx;
	char *ssid_1, *ssid_2, *ssid_3, *ssid_4;		//1:SK_WiFiXXXX		2:SK_VoIP		3:T wifi home	4:SK_WiFiXXXX_2.4
	int n, len, i, rate_len, ssid_idx;

	len = sizeof(pkt->result);

	strcpy(buf, pkt->args);
	args = buf;
	tmp = strsep(&args, "=");
	ydespaces(tmp);

	if (strcmp(tmp, "FREQ") == 0) {
		freq = strsep(&args, ",");
		ydespaces(freq);
		if (strcmp(freq,"2.4G") != 0 && strcmp(freq,"5G") != 0) {
			strcpy(pkt->result, "-1");
			return;
		}
		ydespaces(args);
		tmp = strsep(&args, "=");
		ydespaces(tmp);
		if (tmp == NULL) {
			strcpy(pkt->result, "-1");
			return;
		} else if ((strcmp(tmp, "SSID-NAME") != 0) && (strcmp(tmp, "SSID_IDX") != 0)) {
			strcpy(pkt->result, "-1");
			return;
		}
		ydespaces(args);
	} else {
		strcpy(pkt->result, "-1");
		return;
	}

	if(args == NULL) {
		strcpy(pkt->result, "-1");
		return;
	}

	rate_len = strlen(args);
	if(rate_len == 0) {
		strcpy(pkt->result, "-1");
		return;
	}

	if (strcmp(tmp, "SSID-NAME") == 0) {
		ssid = strsep(&args, ",");
		if (strcmp(freq, "5G") == 0) {
			ssid_1 = holepunch_nv_get_value("nv_5G_ssid");				//1:SK_WiFiXXXX

			if (strcmp(ssid, ssid_1)) {
				strcpy(pkt->result, "-1");
				return;
			}
		} else {
			ssid_1 = holepunch_nv_get_value("nv_2.4G_ssid");			//1:SK_WiFiXXXX
			ssid_2 = holepunch_nv_get_value("nv_2.4G_void_ssid");		//2:SK_VoIP
			ssid_3 = holepunch_nv_get_value("nv_2.4G_t_wifi_ssid");		//3:T wifi home
			ssid_4 = holepunch_nv_get_value("nv_2.4G_multi_ssid");		//4:SK_WiFiXXXX_2.4

			if (strcmp(ssid, ssid_1) && strcmp(ssid, ssid_2) && strcmp(ssid, ssid_3) && strcmp(ssid, ssid_4)) {
				strcpy(pkt->result, "-1");
				return;
			}
		}

		tmp = strsep(&args, "=");

		if (strcmp(tmp, "STATUS")) {
			strcpy(pkt->result, "-1");
			return;
		}

		ydespaces(args);

		if (args == NULL) {
			strcpy(pkt->result, "-1");
			return;
		}

		rate_len = strlen(args);
		if (rate_len == 0) {
			strcpy(pkt->result, "-1");
			return;
		}

		for (i = 0; i < rate_len; i++) {
			if (!isdigit(args[i])) {
				strcpy(pkt->result, "-1");
				return;
			}
		}

		n = 0;
		n += snprintf(&pkt->result[n], len, "FREQ=%s,", freq);
		if (strcmp(freq, "5G") == 0) {											// 5g
			if (strcmp(ssid, ssid_1) == 0) {
				snprintf(param, sizeof(param), "nv_%s_main_ratelimit", freq);
				holepunch_nv_set_value(wlan0_ratelimit, args);
				n += snprintf(&pkt->result[n], len, "SSID=[1]%s,", ssid);
			}
		} else {																// 2.4g
			if (strcmp(ssid, ssid_1) == 0) {
				snprintf(param, sizeof(param), "nv_%s_main_ratelimit", freq);	//1:SK_WiFiXXXX
				holepunch_nv_set_value(wlan1_ratelimit, args);
				n += snprintf(&pkt->result[n], len, "SSID=[1]%s,", ssid);
			} else if (strcmp(ssid, ssid_2) == 0) {
				snprintf(param, sizeof(param), "nv_%s_voip_ratelimit", freq);	//2:SK_VoIP
				holepunch_nv_set_value( wlan1_voip_ratelimit, args);
				n += snprintf(&pkt->result[n], len, "SSID=[2]%s,", ssid);
			} else if (strcmp(ssid, ssid_3) == 0) {
				snprintf(param, sizeof(param), "nv_%s_t_wifi_ratelimit", freq);	//3:T wifi home
				holepunch_nv_set_value(wlan1_t_wifi_ratelimit, args);
				n += snprintf(&pkt->result[n], len, "SSID=[3]%s,", ssid);
			} else {
				snprintf(param, sizeof(param), "nv_%s_multi_ratelimit", freq);	//4:SK_WiFiXXXX_2.4
				holepunch_nv_set_value(wlan1_multi_ratelimit, args);
				n += snprintf(&pkt->result[n], len, "SSID=[5]%s,", ssid);
			}
		}
	} else {
		idx = strsep(&args, ",");
		ssid_idx = strtol(idx, NULL, 10);
		if (ssid_idx < 1 || ssid_idx > 5) {
			strcpy(pkt->result, "-1");
			return;
		}

		if (strcmp(freq, "5G") == 0) {		// 5g
			if (ssid_idx != 1) {
				strcpy(pkt->result, "-1");
				return;
			}
		} else {							// 2.4g
			if (ssid_idx == 4) {
				strcpy(pkt->result, "-1");
				return;
			}
		}

		tmp = strsep(&args, "=");

		if (strcmp(tmp, "STATUS")) {
			strcpy(pkt->result, "-1");
			return;
		}

		ydespaces(args);

		if (args == NULL) {
			strcpy(pkt->result, "-1");
			return;
		}

		rate_len = strlen(args);
		if (rate_len == 0) {
			strcpy(pkt->result, "-1");
			return;
		}

		for (i = 0; i < rate_len; i++) {
			if (!isdigit(args[i])) {
				strcpy(pkt->result, "-1");
				return;
			}
		}

		n = 0;
		n += snprintf(&pkt->result[n], len, "FREQ=%s,", freq);
		if (strcmp(freq, "5G") == 0) {											// 5g
			if (ssid_idx == 1) {
				snprintf(param, sizeof(param), "nv_%s_ssid", freq);				//1:SK_WiFiXXXX
				ssid = holepunch_nv_get_value(param);
				snprintf(param, sizeof(param), "nv_%s_main_ratelimit", freq);
				holepunch_nv_set_value(wlan0_ratelimit, args);
				n += snprintf(&pkt->result[n], len, "SSID=[1]%s,", ssid);
			}
		} else {																// 2.4g
			if (ssid_idx == 1) {
				snprintf(param, sizeof(param), "nv_%s_ssid", freq);				//1:SK_WiFiXXXX
				ssid = holepunch_nv_get_value(param);
				snprintf(param, sizeof(param), "nv_%s_main_ratelimit", freq);
				holepunch_nv_set_value(wlan1_ratelimit, args);
				n += snprintf(&pkt->result[n], len, "SSID=[1]%s,", ssid);
			} else if (ssid_idx == 2) {
				snprintf(param, sizeof(param), "nv_%s_void_ssid", freq);		//2:SK_VoIP
				ssid = holepunch_nv_get_value(param);
				snprintf(param, sizeof(param), "nv_%s_voip_ratelimit", freq);
				holepunch_nv_set_value(wlan1_voip_ratelimit, args);
				n += snprintf(&pkt->result[n], len, "SSID=[2]%s,", ssid);
			} else if (ssid_idx == 3) {
				snprintf(param, sizeof(param), "nv_%s_t_wifi_ssid", freq);		//3:T wifi home
				ssid = holepunch_nv_get_value(param);
				snprintf(param, sizeof(param), "nv_%s_t_wifi_ratelimit", freq);
				holepunch_nv_set_value(wlan1_t_wifi_ratelimit, args);
				n += snprintf(&pkt->result[n], len, "SSID=[3]%s,", ssid);
			} else {
				snprintf(param, sizeof(param), "nv_%s_multi_ssid", freq);		//4:SK_WiFiXXXX_2.4
				ssid = holepunch_nv_get_value(param);
				snprintf(param, sizeof(param), "nv_%s_multi_ratelimit", freq);
				holepunch_nv_set_value(wlan1_multi_ratelimit, args);
				n += snprintf(&pkt->result[n], len, "SSID=[5]%s,", ssid);
			}
		}
	}

	snprintf(rate, sizeof(rate), holepunch_nv_get_value(param));
	n += snprintf(&pkt->result[n], len, "STATUS=%s", rate);
}

static void get_igmp_join_table(struct _HolePunching_PKT *pkt)
{
	struct mcast_group *g;
	struct mcast_mbr *m;
	struct list_head *pos, *pos2;
	struct list_head mc;
	struct list_head upif_grp;
	uint32_t i = 0, phyport, n, len, tmp;
	int count = 0;
	int opmode = -1;
	char c_time[80];
	time_t t;
	char *tmp_op;
	char group_mbr_port[5];

	INIT_LIST_HEAD(&mc);
	INIT_LIST_HEAD(&upif_grp);
	tmp_op = holepunch_nv_get_value("nv_opmode");
	opmode= strtoul(tmp_op, NULL, 10);
	if (opmode == 0)
		if_readgroup(&upif_grp, "eth1");
	read_mcast(&mc, "/proc/rtl865x/igmp");
	len = sizeof(pkt->result);
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
				n += snprintf(&pkt->result[n], len-n, "%s%d|%s:|%d|%d|%s",
					(i==0)?"":",", i+1, inet_ntoa(g->group), group_mbr_port[phyport], phyport, c_time);
				i++;
			}
		}
	}
	mcast_group_free(&mc);
}

static void get_port_status(struct _HolePunching_PKT *pkt)
{
	int i;
    int n, len;
    char inputOctect[5][12], outputOctect[5][12], crc[5][12], now[5][32];
    struct _port_status status[5];
    time_t t;
    unsigned int phy_status[5];

    len = sizeof(pkt->result);

	get_byte_counts(status);
	for(i=0;i<5;i++) {
		phy_status[i]=switch_port_status(i);
		if (phy_status[i] & PHF_LINKUP){
			sprintf(inputOctect[i], "%llu", status[i].inputOCT);
			sprintf(outputOctect[i], "%llu", status[i].outputOCT);
			sprintf(crc[i], "%lu", status[i].CRC);
			t=time(NULL);
			strftime(now[i], 32, "%Y%m%d%H%M%S", localtime(&t));	//YYYYmmddHHMMSS
		} else {
			strcpy(inputOctect[i], "");
			strcpy(outputOctect[i], "");
			strcpy(crc[i], "");
			strcpy(now[i], "");
		}
	}

	n = 0;
	n += snprintf(&pkt->result[n], len, "1|0|WAN|%s|%s|%s|%s,",inputOctect[4], outputOctect[4], crc[4], now[4]);
	n += snprintf(&pkt->result[n], len-n, "2|1|LAN1|%s|%s|%s|%s,",inputOctect[0], outputOctect[0], crc[0], now[0]);
	n += snprintf(&pkt->result[n], len-n, "3|2|LAN2|%s|%s|%s|%s,",inputOctect[1], outputOctect[1], crc[1], now[1]);
	n += snprintf(&pkt->result[n], len-n, "4|3|LAN3|%s|%s|%s|%s,",inputOctect[2], outputOctect[2], crc[2], now[2]);
	n += snprintf(&pkt->result[n], len-n, "5|4|LAN4|%s|%s|%s|%s",inputOctect[3], outputOctect[3], crc[3], now[3]);
}

static void get_resource_status(struct _HolePunching_PKT *pkt)
{
	int n, len;
	char now[32], buf[512];
	time_t t;
	double cpu_idle_load=0, cpu_usage=0;
	int ram_utilization;
	unsigned long total_fla, used_fla, flash_mem_utilization;

	len = sizeof(pkt->result);
	t=time(NULL);
	strftime(now, 32, "%Y%m%d%H%M%S", localtime(&t));	//YYYYmmddHHMMSS

	named_pipe = prequest("cpu_stat");
	if (named_pipe) {
    	if (presponse(named_pipe, buf, sizeof(buf)) > 0)
        	sscanf(buf, "%lf", &cpu_idle_load);
		prelease(named_pipe);
		cpu_usage = 100 - cpu_idle_load;
	}

	if ((int)cpu_usage < 1)
		cpu_usage = 1;

	ram_utilization = memory_used();
	/*boot+cfg+linux + root_fs + b_nvram + nvram = 0x1f00000 SPI flash(GD25Q128) was found at CS0, size 0x2000000 */
	total_fla=0x2000000;
	used_fla=0x1f00000;
	flash_mem_utilization =(used_fla*100)/total_fla;

	n = 0;
	n += snprintf(&pkt->result[n], len, "%d|%d|%lu|%s", (int)cpu_usage, ram_utilization, flash_mem_utilization, now);
}

static void start_port_status_report(struct _HolePunching_PKT *pkt, struct _Port_status *port_status)
{
	char buffer[128];
	char *args, *tmp, *interval=NULL, *count=NULL;
	int len, i;

	strcpy(buffer,pkt->args);
	args = buffer;
	interval = strsep(&args, ",");
	ydespaces(args);
	count=args;

	if (interval && (strncmp(interval, "INTERVAL=", 9)!=0)) {
		strcpy(pkt->result, "-1");
		return;
	}

	tmp=strsep(&interval,"=");
	ydespaces(interval);
	if (interval==NULL) {
		strcpy(pkt->result, "-1");
		return;
	}

	len = strlen(interval);
	if(len==0) {
		strcpy(pkt->result, "-1");
		return;
	}

	for(i=0; i<len; i++) {
		if (!isdigit(interval[i])) {
			strcpy(pkt->result, "-1");
			return;
		}
	}

	port_status->interval=atoi(interval);
	port_status->stop_count=0;

	if(count==NULL) {
		port_status->count=PORT_STATUS_COUNTER_MAX;
	} else if (count && (strncmp(count, "COUNT=", 6)==0)) {
		tmp=strsep(&count,"=");
		ydespaces(count);
		len=strlen(count);
		if(count==NULL) {
			strcpy(pkt->result, "-1");
			return;
		}
		if(len<1) {
			strcpy(pkt->result, "-1");
			return;
		} else {
			for(i=0; i<len; i++) {
				if (!isdigit(count[i])) {
					break;
				}
			}
			if (i==len) {
				port_status->count=atoi(count);
			} else {
				strcpy(pkt->result, "-1");
				return;
			}
		}
	} else {
		strcpy(pkt->result, "-1");
		return;
	}

	strcpy(pkt->result, "1");
	if(First_start == 0) {
		tmr_start(&tmr[TMR_REPORT], 1);
	} else {
		tmr_start(&tmr[TMR_REPORT], port_status->interval);
	}
}

static void stop_port_status_report(struct _HolePunching_PKT *pkt, struct _Port_status *port_status)
{
	strcpy(pkt->result, "1");
	port_status->count=0;
	port_status->stop_count=0;
}

static void start_igmp_join_table_report(struct _HolePunching_PKT *pkt, struct _Igmp_join *igmp_join)
{
	char buffer[128];
	char *args, *tmp, *interval=NULL, *count=NULL;
	int len, i;

	strcpy(buffer,pkt->args);
	args = buffer;
	ydespaces(args);
	interval = strsep(&args, ",");
	ydespaces(interval);
	ydespaces(args);
	count = args;

	if (interval && (strncmp(interval, "INTERVAL=", 9)!=0)) {
		strcpy(pkt->result, "-1");
		return;
	}

	tmp=strsep(&interval, "=");
	ydespaces(interval);
	if (interval==NULL) {
		strcpy(pkt->result, "-1");
		return;
	}
	len=strlen(interval);
	if(len==0) {
		strcpy(pkt->result, "-1");
		return;
	}

	for(i=0; i<len; i++) {
		if (!isdigit(interval[i])) {
			strcpy(pkt->result, "-1");
			return;
		}
	}

	igmp_join->interval=atoi(interval);
	igmp_join->stop_count=0;

	if(count==NULL) {
		igmp_join->count=PORT_STATUS_COUNTER_MAX;
	} else if (count && (strncmp(count, "COUNT=", 6)==0)) {
		tmp=strsep(&count, "=");
		ydespaces(count);
		if(count==NULL) {
			strcpy(pkt->result, "-1");
			return;
		}
		len=strlen(count);
		if(len<1) {
			strcpy(pkt->result, "-1");
			return;
		} else {
			for(i=0; i<len; i++) {
				if (!isdigit(count[i])) {
					break;
				}
			}
			if (i==len) {
				igmp_join->count=atoi(count);
			} else {
				strcpy(pkt->result, "-1");
				return;
			}
		}
	} else {
		strcpy(pkt->result, "-1");
		return;
	}

	strcpy(pkt->result, "1");

	if(First_start == 0) {
		tmr_start(&tmr[TMR_IGMP], 1);
	} else {
		tmr_start(&tmr[TMR_IGMP], igmp_join->interval);
	}
}

static void stop_igmp_join_table_report(struct _HolePunching_PKT *pkt, struct _Igmp_join *igmp_join)
{
	strcpy(pkt->result, "1");
	igmp_join->count=0;
	igmp_join->stop_count=0;
}

static void	start_resource_status_report(struct _HolePunching_PKT *pkt, struct _Resource_status *resource_status)
{
	char buffer[128];
	char *args, *tmp, *interval=NULL, *count=NULL;
	int len, i;

	strcpy(buffer,pkt->args);
	args = buffer;

	interval = strsep(&args, ",");
	ydespaces(args);
	count=args;

	if (interval && (strncmp(interval, "INTERVAL=", 9)!=0)) {
		strcpy(pkt->result, "-1");
		return;
	}

	tmp=strsep(&interval,"=");
	ydespaces(interval);
	if (interval==NULL) {
		strcpy(pkt->result, "-1");
		return;
	}
	len = strlen(interval);
	if(len==0) {
		strcpy(pkt->result, "-1");
		return;
	}
	for(i=0; i<len; i++) {
		if (!isdigit(interval[i])) {
			strcpy(pkt->result, "-1");
			return;
		}
	}

	resource_status->interval=atoi(interval);
	resource_status->stop_count=0;
	if(count==NULL) {
		resource_status->count=PORT_STATUS_COUNTER_MAX;
	} else if (count && (strncmp(count, "COUNT=", 6)==0)) {
		tmp=strsep(&count,"=");
		ydespaces(count);
		len=strlen(count);
		if(count==NULL) {
			strcpy(pkt->result, "-1");
			return;
		}
		if(len<1) {
			strcpy(pkt->result, "-1");
			return;
		} else {
			for(i=0; i<len; i++) {
				if (!isdigit(count[i])) {
					break;
				}
			}
			if (i==len) {
				resource_status->count=atoi(count);
			} else {
				strcpy(pkt->result, "-1");
				return;
			}
		}
	} else {
		strcpy(pkt->result, "-1");
		return;
	}

	strcpy(pkt->result, "1");
	if(First_start == 0) {
		tmr_start(&tmr[TMR_RESOURCE], 1);
	} else {
		tmr_start(&tmr[TMR_RESOURCE], resource_status->interval);
	}
}

static void	stop_resource_status_report(struct _HolePunching_PKT *pkt, struct _Resource_status *resource_status)
{
	strcpy(pkt->result, "1");
	resource_status->count=0;
	resource_status->stop_count=0;
}

static void get_holepunch_version(struct _HolePunching_PKT *pkt)
{
	strcpy(pkt->result, HOLEPUNCH_VERSION);
}

static void set_snmp_value(char *cmd)
{
	FILE *pp = NULL;

	pp = popen(cmd, "r");
	if (pp)
		pclose(pp);
}

static void get_snmp_value(char *cmd, char *value, int len)
{
	FILE *pp = NULL;
	char buf[256];
	char *args[2];
	int n = 0;

	memset(value, 0, len);

	pp = popen(cmd, "r");
	if (pp) {
		fgets(buf, sizeof(buf), pp);
		pclose(pp);
		n = ystrargs(buf, args, _countof(args), "=\n", 0);
		if (n == 2) {
			snprintf(value, len, "%s=%s", args[0], args[1]);
			ydespaces(value);
		}
	}
}

static void get_snmp_result(struct _HolePunching_PKT *pkt)
{
	char getCommunity[32];
	char cmd[128], value[256], snmp_port[8];

	nvram_get_r_def("x_SNMP_PORT", snmp_port, sizeof(snmp_port), "161");
	nvram_get_r_def("x_SNMP_GET_COMMUNITY", getCommunity, sizeof(getCommunity), "iptvshro^_");

	//snmp get command
	sprintf(cmd, "snmpget -m /usr/lib/snmp/SKB-SWHUB-MIB -O 0nQe -c %s 127.0.0.1:%s %s", getCommunity, snmp_port, pkt->args);
	get_snmp_value(cmd, value, sizeof(value));

	sprintf(pkt->result, "%s", value);
}

static void set_snmp_result(struct _HolePunching_PKT *pkt)
{
	char *args[2];
	char buf[80];
	char cmd[128], value[256];
	char snmp_port[8];
	char getCommunity[32], setCommunity[32];
	int n = 0;

	nvram_get_r_def("x_SNMP_PORT", snmp_port, sizeof(snmp_port), "161");
	nvram_get_r_def("x_SNMP_GET_COMMUNITY", getCommunity, sizeof(getCommunity), "iptvshro^_");
	nvram_get_r_def("x_SNMP_SET_COMMUNITY", setCommunity, sizeof(setCommunity), "iptvshrw^_");

	strcpy(buf, pkt->args);
	n = ystrargs(buf, args, _countof(args), ",", 0);

	if (n == 2) {
		snprintf(cmd, sizeof(cmd), "snmpset -m /usr/lib/snmp/SKB-SWHUB-MIB -O 0nQe -c %s 127.0.0.1:%s %s = %s", setCommunity, snmp_port, args[0], args[1]);
		set_snmp_value(cmd);

		snprintf(cmd, sizeof(cmd), "snmpget -m /usr/lib/snmp/SKB-SWHUB-MIB -O 0nQe -c %s 127.0.0.1:%s %s", getCommunity, snmp_port, args[0]);
		get_snmp_value(cmd, value, sizeof(value));
		sprintf(pkt->result, value);
	} else
		sprintf(pkt->result, "-1");
}

void get_snmpwalk(struct _HolePunching_PKT *pkt)
{
	char cmd[256], buf[128];
	FILE *fp = NULL, *pp = NULL;
	char snmp_port[8], getCommunity[32];

	nvram_get_r_def("x_SNMP_PORT", snmp_port, sizeof(snmp_port), "161");
	nvram_get_r_def("x_SNMP_GET_COMMUNITY", getCommunity, sizeof(getCommunity), "iptvshro^_");

	fp = fopen(SNMPWALK_RESULT, "w");

	if (fp) {
		snprintf(cmd, sizeof(cmd), "snmpwalk -m /usr/lib/snmp/SKB-SWHUB-MIB -O 0nQe -c %s 127.0.0.1:%s %s", getCommunity, snmp_port, pkt->args);
		pp = popen(cmd, "r");
		if (pp) {
			while (fgets(buf, sizeof(buf), pp)) {
				fprintf(fp, buf);
			}
			pclose(pp);
		}
		fclose(fp);
	}
}

static void traffic_report(struct _HolePunching_PKT *pkt, struct _traffic_status *traffic_status)
{
	char buffer[128];
	char *args, *tmp, *interval = NULL, *count = NULL;
	int len, i;

	strcpy(buffer,pkt->args);
	args = buffer;
	interval = strsep(&args, ",");
	ydespaces(args);
	count = args;

	if (interval && (strncmp(interval, "INTERVAL=", 9)!=0)) {
		strcpy(pkt->result, "-1");
		return;
	}

	tmp = strsep(&interval,"=");
	ydespaces(interval);
	if (interval == NULL) {
		strcpy(pkt->result, "-1");
		return;
	}

	len = strlen(interval);
	if (len == 0) {
		strcpy(pkt->result, "-1");
		return;
	}

	for (i = 0; i < len; i++) {
		if (!isdigit(interval[i])) {
			strcpy(pkt->result, "-1");
			return;
		}
	}

	traffic_status->interval = atoi(interval);
	traffic_status->stop_count = 0;

	if (count == NULL) {
		traffic_status->count = PORT_STATUS_COUNTER_MAX;
		nvram_set("continue_traffic_report", "1");
		nvram_set("continue_traffic_interval", interval);
		nvram_commit();
	} else if (count && (strncmp(count, "COUNT=", 6) == 0)) {
		tmp = strsep(&count,"=");
		ydespaces(count);
		len = strlen(count);
		if (count == NULL) {
			strcpy(pkt->result, "-1");
			return;
		}
		if (len < 1) {
			strcpy(pkt->result, "-1");
			return;
		} else {
			for (i = 0; i < len; i++) {
				if (!isdigit(count[i])) {
					break;
				}
			}
			if (i == len) {
				traffic_status->count = atoi(count);
			} else {
				strcpy(pkt->result, "-1");
				return;
			}
		}
	} else {
		strcpy(pkt->result, "-1");
		return;
	}

	get_byte_counts(pre_status);
	wirelessClientList(0, pre_wlan0_status);
	wirelessClientList(1, pre_wlan1_status);

	strcpy(pkt->result, "1");
	/*if(First_start == 0)
		tmr_start(&tmr[TMR_TRAFFIC], 1);
	else*/
		tmr_start(&tmr[TMR_TRAFFIC], traffic_status->interval);
}

static void stop_traffic_report(struct _HolePunching_PKT *pkt, struct _traffic_status *traffic_status)
{
	char buf[32];

	strcpy(pkt->result, "1");
	traffic_status->count=0;
	traffic_status->stop_count=0;

	if (nvram_get_r("continue_traffic_report", buf, sizeof(buf))) {
		nvram_unset("continue_traffic_report");
		nvram_unset("continue_traffic_interval");
		nvram_commit();
	}
}

static void send_traffic_report(struct _Hole_punch_info *info, int avg_time)
{
	int i, num = 0;
	char msg[3072];
	char now[32];
	int n, len, cnt = 0, flag_2g = 0, flag_5g = 0;
	unsigned int phy_status[5];
	unsigned long wlan_inByte = 0, wlan_outByte = 0;
	char cpeMac[20], hostname[64] = {0,};
	int dhcpd_pid = 0, opmode = 0;

	time_t t;
	len = sizeof(msg);

	yfcat("/var/sys_op", "%d", &opmode);
	if (opmode == 0) {
		yfcat("/var/run/udhcpd.pid", "%d", &dhcpd_pid);
		if (dhcpd_pid > 0) {
			kill(dhcpd_pid, SIGUSR1);
			usleep(500000);
		}
	}

	t = time(NULL);
	strftime(now, 32, "%Y%m%d%H%M%S", localtime(&t));	//YYYYmmddHHMMSS
	get_byte_counts(now_status);

	flag_5g = wirelessClientList(0, now_wlan0_status);	/* 5G station */
	flag_2g = wirelessClientList(1, now_wlan1_status);	/* 2.4G staion */

	if (avg_time == 0)
		avg_time = 1;

	for (i = 0; i < 5; i++) {
		phy_status[i] = switch_port_status(i);
		if (phy_status[i] & PHF_LINKUP)
			cnt++;
	}

	if (flag_5g)
		cnt += flag_5g;

	if (flag_2g)
		cnt += flag_2g;

	n = 0;
	n += snprintf(&msg[n], len-n, "T=%s\n", get_cmd_type_str(CMD_TYPE_ID_ACK));
	n += snprintf(&msg[n], len-n, "CMD=SEND-TRAFFIC-REPORT\n");
	n += snprintf(&msg[n], len-n, "RESULT=");

	if (phy_status[4] & PHF_LINKUP) {
		num++;
		n += snprintf(&msg[n], len-n, "%d|0|%llu|%llu|%s|%s%s", num, (now_status[4].outputOCT - pre_status[4].outputOCT)/avg_time,
						(now_status[4].inputOCT - pre_status[4].inputOCT)/avg_time, now, info->ap_info.mac_wan, (cnt==num)? "\n" : ",");
	}

	if (phy_status[0] & PHF_LINKUP) {
		num++;
		get_cpemac_list(0, cpeMac, sizeof(cpeMac), hostname, sizeof(hostname));
		n += snprintf(&msg[n], len-n, "%d|1|%llu|%llu|%s|%s|%s%s", num, (now_status[0].outputOCT - pre_status[0].outputOCT)/avg_time,
						(now_status[0].inputOCT - pre_status[0].inputOCT)/avg_time, now, cpeMac, hostname, (cnt==num)? "\n" : ",");
	}

	if (phy_status[1] & PHF_LINKUP) {
		num++;
		get_cpemac_list(1, cpeMac, sizeof(cpeMac), hostname, sizeof(hostname));
		n += snprintf(&msg[n], len-n, "%d|2|%llu|%llu|%s|%s|%s%s", num, (now_status[1].outputOCT - pre_status[1].outputOCT)/avg_time,
						(now_status[1].inputOCT - pre_status[1].inputOCT)/avg_time, now, cpeMac, hostname, (cnt==num)? "\n" : ",");
	}

	if (phy_status[2] & PHF_LINKUP) {
		num++;
		get_cpemac_list(2, cpeMac, sizeof(cpeMac), hostname, sizeof(hostname));
		n += snprintf(&msg[n], len-n, "%d|3|%llu|%llu|%s|%s|%s%s", num, (now_status[2].outputOCT - pre_status[2].outputOCT)/avg_time,
						(now_status[2].inputOCT - pre_status[2].inputOCT)/avg_time, now, cpeMac, hostname, (cnt==num)? "\n" : ",");
	}

	if (phy_status[3] & PHF_LINKUP) {
		num++;
		get_cpemac_list(3, cpeMac, sizeof(cpeMac), hostname, sizeof(hostname));
		n += snprintf(&msg[n], len-n, "%d|4|%llu|%llu|%s|%s|%s%s", num, (now_status[3].outputOCT - pre_status[3].outputOCT)/avg_time,
						(now_status[3].inputOCT - pre_status[3].inputOCT)/avg_time, now, cpeMac, hostname, (cnt==num)? "\n" : ",");
	}

	/* check 2.4G station */
	if (flag_2g) {
	    for (i = 0; i < flag_2g; i++) {
	        match_wlmac_traffic(i, &wlan_outByte, &wlan_inByte, now_wlan1_status, pre_wlan1_status, cpeMac, sizeof(cpeMac), hostname, sizeof(hostname));
		    num++;
		    n += snprintf(&msg[n], len-n, "%d|%d|%lu|%lu|%s|%s|%d|%s|%s%s", num, (10000 + i), wlan_outByte/avg_time, wlan_inByte/avg_time, now, cpeMac, now_wlan1_status[i].rssi, now_wlan1_status[i].txrate, hostname, (cnt==num)? "\n" : ",");
		}
	}

	/* check 5G station */
	wlan_outByte = 0;
	wlan_inByte = 0;
	if (flag_5g) {
	    for (i = 0; i < flag_5g; i++) {
	        match_wlmac_traffic(i, &wlan_outByte, &wlan_inByte, now_wlan0_status, pre_wlan0_status, cpeMac, sizeof(cpeMac), hostname, sizeof(hostname));
		    num++;
		    n += snprintf(&msg[n], len-n, "%d|%d|%lu|%lu|%s|%s|%d|%s|%s%s", num, (20000 + i), wlan_outByte/avg_time, wlan_inByte/avg_time, now, cpeMac, now_wlan0_status[i].rssi, now_wlan0_status[i].txrate, hostname, (cnt==num)? "\n" : ",");
		}
	}

	get_byte_counts(pre_status);
	wirelessClientList(0, pre_wlan0_status);
	wirelessClientList(1, pre_wlan1_status);

	send_pkt(info, msg, n, 1);
}

static void set_admin_pw_init(struct _HolePunching_PKT *pkt)
{
	unsigned char mac[6] = {0,};
	char passwd[128] = {0,}, user_pw[128] = {0,};

	apmib_get(MIB_HW_NIC1_ADDR, mac);
	snprintf(passwd, sizeof(passwd), "%02X%02X%02X_admin", mac[3], mac[4], mac[5]);
	cal_sha256(passwd, user_pw);
	nvram_set("x_USER_PASSWORD", user_pw);
	nvram_commit();
	strcpy(pkt->result, "1");
}

static void ack_result(struct _HolePunching_PKT *pkt, struct _Port_status *port_status, struct _Igmp_join *igmp_join, struct _Resource_status *resource_status, struct _traffic_status *traffic_status)
{
	switch(pkt->cmd)
	{
		case CMD_ID_RESET :
			strcpy(pkt->result, "1");
			tmr_start(&tmr[TMR_REBOOT], 1);
			break;
		case CMD_GET_WIFI_STATUS :
			get_wifi_status(pkt);
			break;
		case CMD_SET_WIFI_STATUS :
			set_wifi_status(pkt);
			break;
		case CMD_GET_SSID_STATUS :
			get_ssid_status(pkt);
			break;
		case CMD_SET_SSID_STATUS :
			set_ssid_status(pkt);
			break;
		case CMD_GET_SSID_RATE :
			get_ssid_rate(pkt);
			break;
		case CMD_SET_SSID_RATE :
			set_ssid_rate(pkt);
			break;
		case CMD_GET_IGMP_JOIN_TABLE :
			get_igmp_join_table(pkt);
			break;
		case CMD_GET_PORT_STATUS :
			get_port_status(pkt);
			break;
		case CMD_GET_RESOURCE_STATUS :
			get_resource_status(pkt);
			break;
		case CMD_START_PORT_STATUS_REPORT :
			start_port_status_report(pkt, port_status);
			break;
		case CMD_STOP_PORT_STATUS_REPORT :
			stop_port_status_report(pkt, port_status);
			break;
		case CMD_START_IGMP_JOIN_TABLE_REPORT :
			start_igmp_join_table_report(pkt, igmp_join);
			break;
		case CMD_STOP_IGMP_JOIN_TABLE_REPORT :
			stop_igmp_join_table_report(pkt, igmp_join);
			break;
		case CMD_START_RESOURCE_STATUS_REPORT :
			start_resource_status_report(pkt, resource_status);
			break;
		case CMD_STOP_RESOURCE_STATUS_REPORT :
			stop_resource_status_report(pkt, resource_status);
			break;
		case CMD_GET_VERSION :
			get_holepunch_version(pkt);
			break;
		case CMD_GET_SNMP :
			get_snmp_result(pkt);
			break;
		case CMD_SET_SNMP :
			set_snmp_result(pkt);
			break;
		case CMD_GET_SNMPWALK :
			get_snmpwalk(pkt);
			break;
		case CMD_TRAFFIC_REPORT :
			traffic_report(pkt, traffic_status);
			break;
		case CMD_STOP_TRAFFIC_REPORT :
			stop_traffic_report(pkt, traffic_status);
			break;
		case CMD_SET_ADMIN_PW_INIT :
			set_admin_pw_init(pkt);
			break;
		default :
			break;
	}
}

static int send_holepuhching_ack(struct _Hole_punch_info *info, struct _HolePunching_PKT *pkt, struct _Port_status *port_status, struct _Igmp_join *igmp_join, struct _Resource_status *resource_status, struct _traffic_status *traffic_status)
{
	int ret = 0, i = 0;
	char msg[4096], line[256];
	char *args[2];
	FILE *fp;
	int n, len;
	struct _AP_info *ap_info;
	ap_info = &(info->ap_info);
	len = sizeof(msg);

	ack_result(pkt, port_status, igmp_join, resource_status, traffic_status);

	//check to SNMP WALK
	if (access(SNMPWALK_RESULT, F_OK) == 0) {
		fp = fopen(SNMPWALK_RESULT, "r");
		if (fp) {
			while (fgets(line, sizeof(line), fp)) {
				ystrargs(line, args, _countof(args), "=\n", 0);
				n = 0;
				n += snprintf(&msg[n], len-n, "T=%s\n", get_cmd_type_str(CMD_TYPE_ID_ACK));
				n += snprintf(&msg[n], len-n, "CMD=%s\n", get_cmd_str(pkt->cmd));
				n += snprintf(&msg[n], len-n, "RESP_SEQ=%d\n", pkt->seq);
				n += snprintf(&msg[n], len-n, "SNMP_WALK_SEQ=%d\n", ++i);
				n += snprintf(&msg[n], len-n, "RESULT=%s=%s\n", (args[0])? :"", (args[1])? : "");
				send_pkt(info, msg, n, 1);
			}
			fclose(fp);
		}
		n = 0;
		n += snprintf(&msg[n], len-n, "T=%s\n", get_cmd_type_str(CMD_TYPE_ID_ACK));
		n += snprintf(&msg[n], len-n, "CMD=%s\n", get_cmd_str(pkt->cmd));
		n += snprintf(&msg[n], len-n, "RESP_SEQ=%d\n", pkt->seq);
		n += snprintf(&msg[n], len-n, "SNMP_WALK_END=1\n");
		n += snprintf(&msg[n], len-n, "RESULT=%s\n", pkt->result);
		send_pkt(info, msg, n, 1);
		unlink(SNMPWALK_RESULT);
	} else {
		n = 0;
		n += snprintf(&msg[n], len-n, "T=%s\n", get_cmd_type_str(CMD_TYPE_ID_ACK));
		n += snprintf(&msg[n], len-n, "CMD=%s\n", get_cmd_str(pkt->cmd));
		n += snprintf(&msg[n], len-n, "RESP_SEQ=%d\n", pkt->seq);
		n += snprintf(&msg[n], len-n, "RESULT=%s\n", pkt->result);
		send_pkt(info, msg, n, 1);
	}

	return ret;
}

static int handle_command(char *msg, int recvLen, struct sockaddr_in *fromAddr, struct _Hole_punch_info *info, struct _Port_status *port_status, struct _Igmp_join *igmp_join, struct _Resource_status *resource_status, struct _traffic_status *traffic_status)
{
	char buffer[128];
	char *value, *name;
	char *fmem;
	key_variable *v;

	if (fromAddr->sin_addr.s_addr == info->report_server_ip || fromAddr->sin_addr.s_addr == info->control_server_ip) {
		struct _HolePunching_PKT hole_punching_pkt;
		memset(&hole_punching_pkt, 0, sizeof(struct _HolePunching_PKT));
		// CMD parsing
		fmem = msg;
		while ( (fmem = read_lines(fmem, buffer, sizeof(buffer))) ) {
			value = buffer;
			name = strsep(&value, "=");
			ydespaces(value);
			ydespaces(name);
			if (!name || !value)
				continue;
			for (v=get_key_tbl(); v->name; v++) {
				if (!strcmp(v->name, name))
					hole_punching_pkt_set(v->id, (void *)value, &hole_punching_pkt);
			}
		}
		// validate pkt
		if ((hole_punching_pkt.cmd_type==0) || (hole_punching_pkt.cmd_type==CMD_TYPE_ID_END) \
					|| (hole_punching_pkt.cmd==0) || (hole_punching_pkt.cmd==CMD_ID_END)) {
						return 0;
		}

		// send ACK
		if (hole_punching_pkt.need_ack==1)
			send_holepuhching_ack(info, &hole_punching_pkt, port_status, igmp_join, resource_status, traffic_status);

		switch (hole_punching_pkt.cmd) {
			case CMD_GET_REPORT_SVR_INFO:
				if ((tmr[TMR_REPORT].resp_seq) == (info->seq)) {
					char *ip, *port;
					in_addr_t addr;

					port = hole_punching_pkt.result;
					ip = strsep(&port, ":");
					ydespaces(port);
					ydespaces(ip);
					if (port) {
						addr = inet_addr(ip);
						if ( (atoi(port)>0) && (ntohl(addr)>0)) {
							info->report_server_ip = addr;
							info->report_server_port = htons(atoi(port));
						}
					}
				}
				break;
			case CMD_SET_WIFI_STATUS:
			case CMD_SET_SSID_STATUS:
			case CMD_SET_SSID_RATE:
				if(strcmp(hole_punching_pkt.result, "-1")) {
					save_change_status();
					reboot();
				}
				break;
			default:
				break;
		}
	} else {
		return 0;
	}
	return 1;
}

static int holepunching_main(struct _Hole_punch_info *info)
{
	int ret, res;
	struct _Port_status port_status;
	struct _Igmp_join igmp_join;
	struct _Resource_status resource_status;
	struct _traffic_status traffic_status;
	struct timeval tv;
	struct sockaddr_in fromAddr;
	unsigned int fromLen;
	int recvLen;
	fd_set readfds, copy_reads;
	char msg[1024];
	unsigned long now;
	int delta, traffic_report, tarffic_interval;

	FD_ZERO(&readfds);
	FD_SET(info->sock_fd, &readfds);

	now = get_uptime();

	tmr_start(&tmr[TMR_KA], 1);
	tmr_start(&tmr[TMR_SVRPOLL], Send_report_time+1);
	tmr_stop(&tmr[TMR_REPORT]);
	tmr_stop(&tmr[TMR_IGMP]);
	tmr_stop(&tmr[TMR_RESOURCE]);
	tmr_stop(&tmr[TMR_TRAFFIC]);
	tmr_stop(&tmr[TMR_REBOOT]);

	tmr[TMR_REBOOT].exp = 0;
	tmr[TMR_IGMP].exp = 0;
	tmr[TMR_RESOURCE].exp = 0;
	tmr[TMR_REPORT].exp = 0;
	tmr[TMR_TRAFFIC].exp = 0;

	if ((traffic_report = nvram_atoi("continue_traffic_report", 0))) {
		tarffic_interval = nvram_atoi("continue_traffic_interval", 1);
		get_byte_counts(pre_status);
		wirelessClientList(0, pre_wlan0_status);
		wirelessClientList(1, pre_wlan1_status);
		traffic_status.interval=tarffic_interval;
		traffic_status.stop_count=0;
		traffic_status.count=PORT_STATUS_COUNTER_MAX;
		tmr_start(&tmr[TMR_TRAFFIC], tarffic_interval);
	}

	while(g_run) {
		if (info->sock_fd < 0) {
			g_run=0;
			break;
		}

		copy_reads = readfds;
		delta = tmr_get_next_delta(get_uptime());

		tv.tv_sec = TICK2SEC(delta);
		tv.tv_usec = 0;

		ret = select(info->sock_fd+1, &copy_reads, NULL, NULL, &tv);
		if (ret == 0) {
			now = get_uptime();

			if (tmr_expired(now, &tmr[TMR_KA])) {
				send_holepunching_keep_live(info);
				tmr[TMR_KA].exp = now + SEC2TICK(safe_atoi(holepunch_dv_get_value("dv_holepunch_control_interval"), 60));
			}

#if 0
/* APACRTL-540 */
			if (tmr_expired(now, &tmr[TMR_SVRPOLL])) {
				send_get_report_svr_info(info);
				tmr[TMR_SVRPOLL].exp = get_uptime() + SEC2TICK(Send_report_time);
			}
#endif

			if (tmr_expired(now, &tmr[TMR_REPORT])) {
				if ((port_status.count!=PORT_STATUS_COUNTER_MAX)&&(++port_status.stop_count > port_status.count)) {
					tmr[TMR_REPORT].enabled=0;
					port_status.count=0;
					port_status.stop_count=0;
				} else {
					send_port_status_report(info);
					tmr[TMR_REPORT].exp = get_uptime()+SEC2TICK(port_status.interval);
				}
			}

			if (tmr_expired(now, &tmr[TMR_IGMP])) {
				if ((igmp_join.count!=PORT_STATUS_COUNTER_MAX)&&(++igmp_join.stop_count > igmp_join.count)) {
					tmr[TMR_IGMP].enabled=0;
					igmp_join.count=0;
					igmp_join.stop_count=0;
				} else {
					send_igmp_join_table_report(info);
					tmr[TMR_IGMP].exp = get_uptime()+SEC2TICK(igmp_join.interval);
				}
			}

			if (tmr_expired(now, &tmr[TMR_RESOURCE])) {
				if ((resource_status.count!=PORT_STATUS_COUNTER_MAX)&&(++resource_status.stop_count > resource_status.count)) {
					tmr[TMR_RESOURCE].enabled=0;
					resource_status.count=0;
					resource_status.stop_count=0;
				} else {
					send_resource_status_report(info);
					tmr[TMR_RESOURCE].exp = get_uptime()+SEC2TICK(resource_status.interval);
				}
			}

			if (tmr_expired(now, &tmr[TMR_TRAFFIC])) {
				if ((traffic_status.count!=PORT_STATUS_COUNTER_MAX)&&(++traffic_status.stop_count > traffic_status.count)) {
					tmr[TMR_TRAFFIC].enabled=0;
					traffic_status.count=0;
					traffic_status.stop_count=0;
				} else {
					send_traffic_report(info, traffic_status.interval);
					tmr[TMR_TRAFFIC].exp = get_uptime()+SEC2TICK(traffic_status.interval);
				}
			}

			if (tmr_expired(now, &tmr[TMR_REBOOT])) {
				reboot();
				tmr[TMR_REBOOT].enabled=0;
			}

		} else if (ret > 0) {
			int fd_set;

			fd_set = FD_ISSET(info->sock_fd, &copy_reads);
			if (fd_set) {
				fromLen = sizeof(fromAddr);
				memset(msg, 0, sizeof(msg));
				recvLen = recvfrom(info->sock_fd, msg, sizeof(msg), 0,  (struct sockaddr *)&fromAddr, &fromLen);
				if (recvLen > 0) {
					res = handle_command(msg, recvLen, &fromAddr, info, &port_status, &igmp_join, &resource_status, &traffic_status);
				}
			}
		}
		if(!g_run)
			break;
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int pid;
	char *debug;
	char *enable;

	if ((pid = test_pid(HOLEPUNCH_PID_FILE)) > 1) {
		kill(pid, SIGTERM);
		fprintf(stderr, "holepunch has been restart\n");
	}

	enable = holepunch_dv_get_value("dv_hole_enable");
	pid = safe_atoi(enable, 1);
	if (pid==0) {
		fprintf(stderr, "holepunch not enable\n");
		exit(1);
	}
	write_pid(HOLEPUNCH_PID_FILE);
	signal(SIGTERM, sig_handler);

	debug = holepunch_dv_get_value("dv_holepunch_dbg");
	if(debug)
		g_debug_flag = strtoul(debug, NULL, 10);
	else
		g_debug_flag = 0;

	wait_connect_wan();
	sleep(10); // wait firewall done.

	init_ap_info(&g_info);
	dump_ap_info(&g_info);

	while(1){
		g_info.sock_fd = open_socket(&g_info.sock_fd);
		if(g_info.sock_fd!=-1)
			break;
		sleep(10);
	}
#if 0
/* APACRTL-540 */
// Connect control server (Get report server info)
	while (1){
		if (connect_control_server(&g_info))
			break;
		sleep(10);
		get_control_server_info(&g_info);
	};
#endif

	dump_ap_info(&g_info);

	holepunching_main(&g_info);
	return 1;
}