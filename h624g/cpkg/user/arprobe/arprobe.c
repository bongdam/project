#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <signal.h>
#include <linux/if_arp.h>
#include <linux/filter.h>
#include <syslog.h>
#include <sys/syscall.h>
#include <time.h>
#include <dvflag.h>
#include <byteswap.h>
#include <endian.h>
#include "libytool.h"

#define PID_FILE	"/var/run/arprobe.pid"
#ifndef bool
#define bool    	int
#endif

#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif

#define SEC2MS(s)	((s) * 1000)
#define MIN2MS(m)	SEC2MS((m) * 60)

#if defined(__BIG_ENDIAN__) || (__BYTE_ORDER == __BIG_ENDIAN)
#define btonl(p)   ((((unsigned long int)(p)[0] & 0xff) << 24) | \
                    (((unsigned long int)(p)[1] & 0xff) << 16) | \
                    (((unsigned long int)(p)[2] & 0xff) <<  8) | \
                    (((unsigned long int)(p)[3] & 0xff)))
#else
#define btonl(p)   ((((unsigned long int)(p)[3] & 0xff) << 24) | \
                    (((unsigned long int)(p)[2] & 0xff) << 16) | \
                    (((unsigned long int)(p)[1] & 0xff) <<  8) | \
                    (((unsigned long int)(p)[0] & 0xff)))
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

struct ifaddrs_s {
	char ifa_name[16];
	int ifa_ifindex;
	in_addr_t ifa_addr;	/* protocol address */
	char ifa_hwaddr[6];	/* hardware address */
};

struct arpMsg {
	struct ethhdr ethhdr;	/* Ethernet header */
	u_short htype;		/* hardware type (must be ARPHRD_ETHER) */
	u_short ptype;		/* protocol type (must be ETH_P_IP) */
	u_char hlen;		/* hardware address length (must be 6) */
	u_char plen;		/* protocol address length (must be 4) */
	u_short operation;	/* ARP opcode */
	u_char sHaddr[6];	/* sender's hardware address */
	u_char sInaddr[4];	/* sender's IP address */
	u_char tHaddr[6];	/* target's hardware address */
	u_char tInaddr[4];	/* target's IP address */
	u_char pad[18];		/* pad for min. Ethernet payload (60 bytes) */
};

/* ---- Private Variables ------------------------------------------------ */
static struct sock_filter fcode[] = {
	{0x28, 0, 0, 0x0000000c},	/* (000) ldh  [12]                     */
	{0x15, 0, 5, 0x00000806},	/* (001) jeq  #0x806      jt 2    jf 7 */
	{0x28, 0, 0, 0x00000014},	/* (002) ldh  [20]                     */
	{0x15, 0, 3, 0x00000002},	/* (003) jeq  #0x2        jt 4    jf 7 */
	{0x20, 0, 0, 0x0000001c},	/* (004) ld   [28]                     */
	{0x15, 0, 1, 0x00000000},	/* (005) jeq  #0xXXXXXXXX jt 6    jf 7 */
	{0x6, 0, 0, 0x0000ffff},	/* (006) ret  #65535                   */
	{0x6, 0, 0, 0x00000000},	/* (007) ret  #0                       */
};

static struct sock_fprog arp_filter = {
	sizeof(fcode) / sizeof(struct sock_filter),
	fcode
};

/* ---- Private Function Prototypes -------------------------------------- */
/* ---- Extern  Function Prototypes -------------------------------------- */
static const u_char *eth_broadcast_addr = (u_char *)"\xff\xff\xff\xff\xff\xff";
static const u_char *eth_zero_addr = (u_char *)"\x00\x00\x00\x00\x00\x00";
static int ffd, sk = -1;
static int sdmz_mode;
static int verbose;
static struct arpMsg req;
static struct sockaddr_ll dest;
static struct ifaddrs_s ifaddress;

#define say(fmt, args...) \
	do {\
		if (verbose) printf(fmt, ## args);\
	} while (0)

static inline int conflict(int bset, u_long ip, const u_char *ea)
{
	return yecho("/proc/net/ip_conflict",
		     "%d %u.%u.%u.%u/%02x:%02x:%02x:%02x:%02x:%02x\n",
		     !!bset, NIPQUAD(ip),
		     ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]);
}

static long monotonic_ms(void)
{
	struct timespec ts;
	syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &ts);
	return (long)(ts.tv_sec * 1000UL + ts.tv_nsec / 1000000);
}

static char *read_line(const char *path, char *s, size_t size)
{
	char fmt[16];

	s[0] = '\0';
	sprintf(fmt, "%%%ds", size - 1);
	yfcat(path, fmt, s);
	ydespaces(s);
	return s;
}

static int fget_and_test_pid(const char *filename)
{
	int pid;
	if (yfcat(filename, "%d", &pid) != 1 || kill(pid, 0))
		pid = 0;
	return pid;
}

static int pid_of_dhcpclnt(const char *name)
{
	char buf[64];
	snprintf(buf, sizeof(buf), "/etc/udhcpc/udhcpc-%s.pid", name);
	return fget_and_test_pid(buf);
}

static int socket_raw(struct ifaddrs_s *pif)
{
	int s;
	struct sockaddr_ll sock;

	if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
		perror("socket");
		return -1;
	}

	sock.sll_family = AF_PACKET;
	sock.sll_protocol = htons(ETH_P_ARP);
	sock.sll_ifindex = pif->ifa_ifindex;
	if (bind(s, (struct sockaddr *)&sock, sizeof(sock)) < 0) {
		close(s);
		return -1;
	}

	fcode[5].k = ntohl(pif->ifa_addr);
	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &arp_filter, sizeof(arp_filter)) != 0)
		perror("SO_ATTACH_FILTER");

	return s;
}

static int get_ifaddrs(struct ifaddrs_s *I)
{
#define SIN(a)	((struct sockaddr_in *)(&(a)))
	char buf[80];
	struct ifreq ifr;
	int s, res;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;
	I->ifa_addr = INADDR_ANY;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, I->ifa_name, IFNAMSIZ);
	if ((res = ioctl(s, SIOCGIFINDEX, &ifr)) == 0) {
		I->ifa_ifindex = ifr.ifr_ifindex;
		if ((res = ioctl(s, SIOCGIFHWADDR, &ifr)) == 0) {
			memcpy(I->ifa_hwaddr, ifr.ifr_hwaddr.sa_data, 6);
			if (sdmz_mode)
				I->ifa_addr = inet_addr(read_line("/var/wan_ip", buf, sizeof(buf)));
			else if ((res = ioctl(s, SIOCGIFADDR, &ifr)) == 0)
				I->ifa_addr = SIN(ifr.ifr_addr)->sin_addr.s_addr;
		}
	}
	close(s);

	return (res || (I->ifa_addr == INADDR_ANY) || (I->ifa_addr == INADDR_NONE)) ? -1 : 0;
}

static int build_garp(struct arpMsg *arp, struct ifaddrs_s *pif)
{
	memset(arp, 0, sizeof(struct arpMsg));
	memcpy(arp->ethhdr.h_dest, eth_broadcast_addr, 6);
	memcpy(arp->ethhdr.h_source, pif->ifa_hwaddr, 6);
	arp->ethhdr.h_proto = htons(ETH_P_ARP);
	arp->htype = htons(ARPHRD_ETHER);
	arp->ptype = htons(ETH_P_IP);
	arp->hlen = 6;
	arp->plen = 4;
	arp->operation = htons(ARPOP_REQUEST);
#ifndef RFC5227_COMPLIANT
	memcpy(arp->sInaddr, &pif->ifa_addr, 4);
#endif
	memcpy(arp->sHaddr, pif->ifa_hwaddr, 6);
	memcpy(arp->tInaddr, &pif->ifa_addr, 4);
	return 0;
}

static int send_garp(struct arpMsg *arp, struct ifaddrs_s *pif)
{
	int fd;

	fd = socket_raw(pif);
	if (fd < 0)
		return -1;

	memset(&dest, 0, sizeof(dest));
	dest.sll_family = AF_PACKET;
	dest.sll_protocol = htons(ETH_P_ARP);
	dest.sll_ifindex = pif->ifa_ifindex;
	dest.sll_halen = 6;
	memcpy(dest.sll_addr, eth_broadcast_addr, 6);

	if (sendto(fd, arp, sizeof(struct arpMsg), 0,
		   (struct sockaddr *)&dest, sizeof(dest)) <= 0) {
		close(fd);
		perror("sendto");
		return -1;
	}
	return fd;
}

static int write_status(int fd, bool bset, unsigned long ip, const u_char *ea)
{
	unsigned int val[2];

	conflict(bset, ip, ea);
	val[0] = (bset) ? DF_IPADDRDUP : 0;
	val[1] = DF_IPADDRDUP;
	return (write(fd, val, sizeof(val)) == sizeof(val)) ? 0 : -1;
}

static void exit_arprobe(int signo)
{
	close(ffd);
	if (sk != -1)
		close(sk);
	unlink(PID_FILE);
	_exit(-1);
}

static void usage(void)
{
	fprintf(stderr, "Usage: arprobe [OPTION]...\n"
			"  -i inf  WAN interface name\n"
			"  -s      Super DMZ mode\n"
			"  -b      DHCP client for WAN\n"
			"  -v      Verbose.\n");
	exit(EXIT_SUCCESS);
}


int main(int argc, char *argv[])
{
	bool found = 0, replied = 0;
	struct pollfd pfd[2];
	long expiry, now, timeout, tstamp;
	unsigned int flag, oldflag;
	struct arpMsg resp;
	bool probing;
	char buf[64];
	int inited, pid, status, opt, dhcpc = 0;
/* APACRTL-94 */
	int repeater_mode = 0;
	unsigned int link_flg = 0;
	unsigned int cmask;

	if (fget_and_test_pid(PID_FILE) > 0)
		return 0;

	memset(&ifaddress, 0, sizeof(struct ifaddrs_s));

	while ((opt = getopt(argc, argv, "i:bvsr")) != -1) {
		switch (opt) {
		case 'i':
			snprintf(ifaddress.ifa_name, sizeof(ifaddress.ifa_name), "%s", optarg);
			break;
		case 'b':
			dhcpc = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 's':
			sdmz_mode = 1;
			break;
/* APACRTL-94 */
		case 'r':
			repeater_mode = 1;
			break;
		default:
			usage();
			break;
		}
	}

/* APACRTL-94 */
	if (repeater_mode) {
		cmask = DF_WLCLNT_UP|DF_IPADDRDUP|DF_WANBOUND;
		link_flg = DF_WLCLNT_UP;
	} else {
		cmask = DF_WANLINK|DF_IPADDRDUP|DF_WANBOUND;
		link_flg = DF_WANLINK;
	}

	if (ifaddress.ifa_name[0] == '\0')
		usage();

	daemon(0, 1);

	signal(SIGTERM, exit_arprobe);
	ywrite_pid(PID_FILE);

	ffd = open("/proc/dvflag", O_RDWR);
	assert(ffd > -1);

	flag = cmask;
	ioctl(ffd, DVFLGIO_SETMASK, &flag);
	read(ffd, (void *)&flag, sizeof(flag));
	probing = test_all_bits(link_flg|DF_WANBOUND, flag);

	pfd[0].fd = ffd;
	pfd[0].events = POLLIN;
	pfd[1].events = POLLIN;

	tstamp = 0;
	expiry = monotonic_ms();

	for (oldflag = flag & cmask;;) {
		say("%sfound, %sreplied and %s probe\n",
		    found ? "" : "not ", replied ? "" : "un", probing ? "will" : "won't");
		if (probing == TRUE && !get_ifaddrs(&ifaddress)) {
			build_garp(&req, &ifaddress);
			sk = send_garp(&req, &ifaddress);
			if (sk != -1)
				probing = FALSE;
		}

		now = monotonic_ms();
		if (sk != -1) {
			pfd[1].fd = sk;
			timeout = SEC2MS(1);
			expiry = now + timeout;
		} else {
			do {
				expiry += MIN2MS(1);		/* absolute delta time */
				if ((timeout = (expiry - now)) <= 0)
					continue;
			} while (0);
		}

		buf[0] = '\0';
		for (found = replied = FALSE;
		     !found && timeout > 0;
		     timeout = (expiry - (int)monotonic_ms())) {
			status = poll(pfd, (sk != -1) ? 2 : 1, timeout);
			if (status == 0)
				break;
			else if (status < 0) {
				if (errno != EINTR) {
					perror("poll");
					break;
				}
				continue;
			}
			if (pfd[0].revents) {
				read(ffd, (void *)&flag, sizeof(flag));
				inited = !!(flag & DF_INITED);
				flag &= cmask;
				say("flag-bits are%s%s%s (%x/%x)\n",
				    (flag & DF_IPADDRDUP) ? " dup" : "",
				    (flag & DF_WANLINK) ? " linkup" : "",
				    (flag & DF_WANBOUND) ? " bound" : "", oldflag, flag);

				if (dhcpc) {
					/* In transition from 'deconfig' to 'bound'
					   gratuitous arp would be implemented by dhcp client.
					   The linkage transition is the only case.
					 */
					if (test_inverted_set(link_flg, oldflag, flag)) {
						if ((tstamp && ((monotonic_ms() - tstamp) > 1500)) ||
						    (!tstamp && inited)) {
							pid = pid_of_dhcpclnt(ifaddress.ifa_name);
							if (pid > 1)
								kill(pid, SIGUSR1);
						} else
							probing = test_all_bits(link_flg|DF_WANBOUND, flag);
					} else if (test_inverted_clear(link_flg, oldflag, flag))
						tstamp = monotonic_ms();
				} else if (test_inverted_set(link_flg, oldflag, flag) ||
					   test_inverted_set(DF_WANBOUND, oldflag, flag))
					probing = test_all_bits(link_flg|DF_WANBOUND, flag);

				if (test_inverted_set(DF_IPADDRDUP, oldflag, flag)) {
					expiry = monotonic_ms();
					found = TRUE;
					probing = FALSE;
					read_line("/proc/net/ip_conflict", buf, sizeof(buf));
				}
				oldflag = flag;

				if (sk < 0 && probing)
					break;
			}

			if (sk != -1 && pfd[1].revents) {
				if ((recv(sk, &resp, sizeof(resp), 0) > 0) &&
				    (resp.operation == htons(ARPOP_REPLY)) &&
				    !memcmp(resp.sInaddr, &ifaddress.ifa_addr, sizeof(in_addr_t))) {
					replied = TRUE;
					sprintf(buf, "%u.%u.%u.%u %02x:%02x:%02x:%02x:%02x:%02x",
						NIPQUAD(resp.sInaddr),
						resp.sHaddr[0], resp.sHaddr[1], resp.sHaddr[2],
						resp.sHaddr[3], resp.sHaddr[4], resp.sHaddr[5]);
				}
			}
		}

		if (sk != -1) {
			close(sk);
			sk = -1;
		}

		if (found || replied) {
			syslog(LOG_INFO, "WAN IP 충돌 %s", buf);
			if (dhcpc) {
				if (replied)
					write_status(ffd, 1, btonl(resp.sInaddr), resp.sHaddr);
				/* Recording a duplicated hardware address must
				 * be prior to sending signal to dhcpc.
				 */
				if ((pid = pid_of_dhcpclnt(ifaddress.ifa_name)) > 1) {
					say("Send signal to udhcpc %d\n", pid);
					kill(pid, SIGHUP);
					sleep(1);
					kill(pid, SIGUSR1);
				}
				write_status(ffd, 0, INADDR_ANY, eth_zero_addr);
			} else if (replied)
				write_status(ffd, 0, INADDR_ANY, eth_zero_addr);
			probing = FALSE;
		} else
			conflict(0, INADDR_ANY, eth_zero_addr);
	}

	return 0;
}
