/* jihyun@davo 150614 jcode#1 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <bcmnvram.h>
#include <linux/igmp.h>
#include <syslog.h>
#include <shutils.h>
#include <libytool.h>
#include <brdio.h>

/* IGMP group address */
#define ALL_SYSTEMS		htonl(0xE0000001)	// General Query - 224.0.0.1
#define ALL_ROUTERS		htonl(0xE0000002)	// Leave - 224.0.0.2
#define ALL_ROUTERS_V3	htonl(0xE0000016)	// Leave - 224.0.0.22
#define ALL_PRINTER		htonl(0xEFFFFFFA)	// notify all printer - 239.255.255.250
#define CLASS_D_MASK	0xE0000000	// the mask that defines IP Class D
#define IPMULTI_MASK	0x007FFFFF	// to get the low-order 23 bits

/* header length */
#define MIN_IP_HEADER_LEN	20
#define IGMP_MINLEN			8

#define RECV_BUF_SIZE	2048

#define IGMP_QUERIER_INTERVAL_SEC	125

static int igmpquerier_status = 1;

void poll_igmpquerier_mgr(unsigned char mrt);
void close_igmpquerier(void);

static int igmp_querier_auto = 1;
static int dv_poll_time;
char *send_buf;
int sock;
struct in_addr InAdr;

/*
 * u_short in_cksum(u_short *addr, int len)
 *
 * Compute the inet checksum
 */
unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	answer = ~sum;
	return (answer);
}

int igmp_inf_create(char *ifname)
{
	int i;
	int ret;

	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0) {
		perror("IGMP socket");
		return -1;
	}

	/* init igmp */
	/* Set reuseaddr, ttl, loopback and set outgoing interface */
	i = 1;
	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&i, sizeof(i));
	if (ret)
		printf("setsockopt SO_REUSEADDR error!\n");
	i = 1;
	ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&i, sizeof(i));
	if (ret)
		printf("setsockopt IP_MULTICAST_TTL error!\n");
	//eddie disable LOOP
	i = 0;
	ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void *)&i, sizeof(i));
	if (ret)
		printf("setsockopt IP_MULTICAST_LOOP error!\n");
	ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (void *)&InAdr, sizeof(struct in_addr));
	if (ret)
		printf("setsockopt IP_MULTICAST_IF error!\n");

	/* In linux use IP_PKTINFO */
	//IP_RECVIF returns the interface of received datagram
	i = 1;
	ret = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &i, sizeof(i));
	if (ret)
		printf("setsockopt IP_PKTINFO error!\n");

	//ret = fcntl(sock, F_SETFL, O_NONBLOCK);
	//if(ret)
	//      printf("fcntl O_NONBLOCK error!\n");

	return 0;
}

/*
 * igmp_query - send an IGMP Query packet to downstream interface
 *
 * int igmp_query(__u32 dst, __u32 grp,__u8 mrt)
 * Where:
 *  dst		destination address
 *  grp		query group address
 *  MRT		Max Response Time in IGMP header (in 1/10 second unit)
 *
 * Returns:
 *	0	if unable to send
 *	1	packet was sent successfully
 */

int igmp_query(unsigned int dst, unsigned int grp, unsigned char mrt)
{
	struct iphdr *ip;
	struct igmphdr *igmp;
	struct sockaddr_in sdst;

	ip = (struct iphdr *)send_buf;
	ip->saddr = InAdr.s_addr;
	ip->daddr = dst;
	ip->tot_len = MIN_IP_HEADER_LEN + IGMP_MINLEN;
	ip->ttl = 1;

	igmp = (struct igmphdr *)(send_buf + MIN_IP_HEADER_LEN);
	igmp->type = 0x11;
	igmp->code = mrt;
	igmp->group = grp;
	igmp->csum = 0;
	igmp->csum = in_cksum((u_short *) igmp, IGMP_MINLEN);

	bzero(&sdst, sizeof(struct sockaddr_in));
	sdst.sin_family = AF_INET;
	sdst.sin_addr.s_addr = dst;

	if (sendto(sock, igmp, IGMP_MINLEN, 0, (struct sockaddr *)&sdst, sizeof(sdst)) < 0)
		perror("igmpquerier: sendto");

	return 0;
}

int get_igmp_query_received(void)
{
	int flg = 0;

	yfcat("/proc/dv_igmp_query_received", "%d", &flg);
	yecho("/proc/dv_igmp_query_received", "0");
	return flg;
}

#define WAN_PHY_PORT	4
void igmpquerier_sender(unsigned char mrt)
{
	char buf[32] = { 0 };
	long wan_ip = 0;

	yfcat("/var/wan_ip", "%31s", buf);
	inet_pton(AF_INET, buf, &wan_ip);
	if (wan_ip == 0 || !(switch_port_status(WAN_PHY_PORT) & PHF_LINKUP))
		return;

	InAdr.s_addr = wan_ip;

	if (igmp_inf_create("br0") < 0)
		return;

	igmp_query(ALL_SYSTEMS, 0, mrt);
	close(sock);
}

int init_igmp(void)
{
	char buf[32];

	send_buf = malloc(RECV_BUF_SIZE);

	yecho("/proc/dv_igmp_query_to_lan", "1\n");

	nvram_get_r("x_igmp_querier_auto", buf, sizeof(buf));
	if (buf[0] && (atoi(buf) == 1))
		igmp_querier_auto = 1;
	else
		igmp_querier_auto = 0;
	return 0;
}

void poll_igmpquerier_mgr(unsigned char mrt)
{
	if (igmp_querier_auto == 1) {
		if (get_igmp_query_received() == 1) {
			if (igmpquerier_status == 1) {
				syslog(LOG_INFO, "IGMP Querier STOP");
				igmpquerier_status = 0;
			}
			return;
		}
	}
	if (igmpquerier_status == 0) {
		syslog(LOG_INFO, "IGMP Querier Start");
		igmpquerier_status = 1;
	}
	igmpquerier_sender(mrt);
}

int get_ap_mode(void)
{
	int val = 0;
	yfcat("/var/sys_op", "%d", &val);
	return val;
}

int main(int argc, char **argv)
{
	char buf[32];
	struct timeval t;
	int ret;
	unsigned char mrt;
	// AP mode check;
	if (get_ap_mode() != 1)
		return 0;

	yecho("/proc/br_igmpquery", "0\n");

	if (nvram_match_r("x_igmp_querier", "0"))
		return 0;
	openlog("IGMP Querier", 0, 0);

	memset(buf, 0, sizeof(buf));
	nvram_get_r("x_igmp_querier_interval", buf, sizeof(buf));
	if (buf[0] == 0)
		dv_poll_time = IGMP_QUERIER_INTERVAL_SEC;	/* APNRTL-222 */
	else
		dv_poll_time = atoi(buf);

	nvram_get_r_def("x_igmp_general_mrt", buf, sizeof(buf), "100");//default 10sec(in 1/10 second unit)
	mrt = (unsigned char)strtoul(buf, NULL, 10);
	
	printf("Enable IGMP Querier ... Interval[ %d ]\n", dv_poll_time);
	init_igmp();
	syslog(LOG_INFO, "IGMP Querier Start");
	igmpquerier_status = 1;

	while (1) {
		t.tv_sec = dv_poll_time;
		t.tv_usec = 0;

		ret = select(0, 0, 0, 0, &t);

		poll_igmpquerier_mgr(mrt);
	}

	syslog(LOG_INFO, "IGMP Querier Stop");
	igmpquerier_status = 0;
	closelog();

	return 0;
}

void close_igmpquerier(void)
{
	syslog(LOG_INFO, "IGMP Querier Stop");
	igmpquerier_status = 0;
	closelog();
}
