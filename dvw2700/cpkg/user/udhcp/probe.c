#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <features.h>
#if __GLIBC__ >=2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif
#include <linux/filter.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>

#include <dvflag.h>
#include <libytool.h>

#include "packet.h"
#include "debug.h"
#include "dhcpd.h"
#include "options.h"
#include "clientpacket.h"
#include "pidfile.h"

#define LANMASK (DF_LANLINK1 | DF_LANLINK2 | DF_LANLINK3 | DF_LANLINK4)

static struct sock_filter fcodes[] = {
	{ 0x20, 0, 0, 0x00000008 },
	{ 0x15, 0, 2, 0x02030405 },	// 1
	{ 0x28, 0, 0, 0x00000006 },
	{ 0x15, 15,0, 0x00000101 },	// 3
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 4, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 0, 11,0x00000011 },
	{ 0x28, 0, 0, 0x00000036 },
	{ 0x15, 8, 9, 0x00000043 },
	{ 0x15, 0, 8, 0x00000800 },
	{ 0x30, 0, 0, 0x00000017 },
	{ 0x15, 0, 6, 0x00000011 },
	{ 0x28, 0, 0, 0x00000014 },
	{ 0x45, 4, 0, 0x00001fff },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x48, 0, 0, 0x0000000e },
	{ 0x15, 0, 1, 0x00000043 },
	{ 0x6,  0, 0, 0x0000ffff },
	{ 0x6,  0, 0, 0x00000000 }
};

static struct sock_fprog bootp_resp_filter = {
	sizeof(fcodes) / sizeof(struct sock_filter),
	fcodes
};

static int eth_socket(int ifindex, unsigned char *addr)
{
	int fd;
	struct sockaddr_ll sock;

	if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		return -1;

	sock.sll_family = AF_PACKET;
	sock.sll_protocol = htons(ETH_P_ALL);
	sock.sll_ifindex = ifindex;
	if (bind(fd, (struct sockaddr *)&sock, sizeof(sock)) < 0) {
		close(fd);
		return -1;
	}

	fcodes[3].k = (addr[0] << 8) | addr[1];
	fcodes[1].k = (addr[2] << 24) | (addr[3] << 16) | (addr[4] << 8) | addr[5];
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &bootp_resp_filter, sizeof(bootp_resp_filter)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int
send_probe_discover(unsigned long xid, u_int8_t *chaddr, int ifindex)
{
	struct dhcpMessage packet;
	struct vendor {
		char vendor, length;
		char str[sizeof("MSFT 5.0")];
	} vendor_id = { DHCP_VENDOR, sizeof("MSFT 5.0") - 1, "MSFT 5.0" };
	unsigned char cidbuf[12];

	init_header(&packet, DHCPDISCOVER);
	memcpy(packet.chaddr, chaddr, 6);

	cidbuf[OPT_CODE] = DHCP_CLIENT_ID;
	cidbuf[OPT_LEN] = 7;
	cidbuf[OPT_DATA] = 1;
	memcpy(&cidbuf[OPT_DATA + 1], chaddr, 6);
	add_option_string(packet.options, cidbuf);

	add_option_string(packet.options, (unsigned char *)&vendor_id);
	packet.xid = xid;
	packet.flags = htons(0x8000);
	add_requests(&packet);
	return raw_packet(&packet, INADDR_ANY, CLIENT_PORT, INADDR_BROADCAST,
			  SERVER_PORT, MAC_BCAST_ADDR, ifindex);
}

static int
get_eth_packet(struct dhcpMessage *payload, int fd, unsigned char *addr)
{
	int bytes;
	unsigned char buf[sizeof(struct udp_dhcp_packet) + 24];
	struct ethhdr *eh;
	struct udp_dhcp_packet *P = NULL;
#define packet (P[0])
	u_int32_t source, dest;
	u_int16_t check;

	/* 4 align from ip header */
	bytes = read(fd, &buf[2], sizeof(buf) - 2);
	if (bytes < 0) {
		DEBUG(LOG_INFO, "couldn't read on raw listening socket -- ignoring");
		usleep(500000);	/* possible down interface, looping condition */
		return -1;
	}

	if (bytes < (int)(14 + sizeof(struct iphdr) + sizeof(struct udphdr))) {
		DEBUG(LOG_INFO, "message too short, ignoring");
		return -2;
	}

	eh = (struct ethhdr *)&buf[2];
	if (addr)
		memcpy(addr, eh->h_source, ETH_ALEN);

	P = (struct udp_dhcp_packet *)&eh[1];
	if (bytes < ntohs(packet.ip.tot_len))
		return -3;

	/* ignore any extra garbage bytes */
	bytes = ntohs(packet.ip.tot_len);

	/* Make sure its the right packet for us, and that it passes sanity checks */
	if (packet.ip.protocol != IPPROTO_UDP ||
	    packet.ip.version != IPVERSION ||
	    packet.ip.ihl != sizeof(packet.ip) >> 2 ||
	    packet.udp.dest != htons(CLIENT_PORT) ||
	    bytes > (int)sizeof(struct udp_dhcp_packet) ||
	    ntohs(packet.udp.len) != (short)(bytes - sizeof(packet.ip)))
		return -4;

	/* check IP checksum */
	check = packet.ip.check;
	packet.ip.check = 0;
	if (check != checksum(&(packet.ip), sizeof(packet.ip)))
		return -5;

	/* verify the UDP checksum by replacing the header with a psuedo header */
	source = packet.ip.saddr;
	dest = packet.ip.daddr;
	check = packet.udp.check;
	packet.udp.check = 0;
	memset(&packet.ip, 0, sizeof(packet.ip));

	packet.ip.protocol = IPPROTO_UDP;
	packet.ip.saddr = source;
	packet.ip.daddr = dest;
	packet.ip.tot_len = packet.udp.len;	/* cheat on the psuedo-header */
	if (check && check != checksum(&packet, bytes))
		return -6;

	memcpy(payload, &(packet.data), bytes - (sizeof(packet.ip) + sizeof(packet.udp)));
	if (ntohl(payload->cookie) != DHCP_MAGIC)
		return -7;

	return bytes - (sizeof(packet.ip) + sizeof(packet.udp));
#undef packet
}

/* port where a dhcp server is discovered  */
static unsigned int populated = 0;

static unsigned int getplugmask(int fd, int timeout)
{
	struct pollfd pfd;
	unsigned int flg;

	pfd.fd = fd;
	pfd.events = POLLIN;
	poll(&pfd, 1, timeout);

	read(fd, (void *)&flg, sizeof(flg));
	return (flg & LANMASK);
}

static int poll_server(int timeout, unsigned char *addr)
{
	struct pollfd pfd;
	int s, status = -1;
	unsigned long xid;
	struct dhcpMessage packet;
	unsigned char *p;
	int ret, expiry;

	s = eth_socket(server_config.ifindex, server_config.arp);
	if (s < 0)
		return -1;

	xid = random_xid();
	pfd.fd = s;
	pfd.events = POLLIN;

	expiry = monotonic_ms() + timeout;
	send_probe_discover(xid, server_config.arp, server_config.ifindex);

	while (status) {
		timeout = expiry - monotonic_ms();
		if (timeout <= 0)
			break;
		ret = poll(&pfd, 1, timeout);
		if (ret == 0)
			break;
		else if (ret < 0) {
			if (errno != EINTR)
				break;
		} else if (get_eth_packet(&packet, s, addr) > 0) {
			p = get_option(&packet, DHCP_MESSAGE_TYPE);
			if (p && p[0] == DHCPOFFER)
				status = 0;
		}
	}

	close(s);
	return status;
}

int getportbyhaddr(unsigned char *addr)
{
	int fd, port = -1;
	int arg[3];

	fd = open("/proc/rtl865x/l2", O_RDWR);
	if (fd < 0)
		return -1;
	memcpy((void *)arg, addr, 6);
	if (!ioctl(fd, _IO(211, 0), arg))
		port = arg[0];
	close(fd);
	return port;
}

unsigned port_to_mask(int port)
{
	if (port >= 0 && port < 5)
		return (1 << port);	/* -DPRTNR_XXXX */
	return LANMASK;
}

const char *mask_nam(unsigned mask)
{
	switch (mask) {
	case DF_LANLINK1:
		return "LAN1";
	case DF_LANLINK2:
		return "LAN2";
	case DF_LANLINK3:
		return "LAN3";
	case DF_LANLINK4:
		return "LAN4";
	}
	return "----";
}

static void sanction(int give)
{
	yexecl(NULL, "iptables %s OUTPUT -o br0 -p 2 -j DROP", give ? "-I" : "-D");
	yexecl(NULL, "aclwrite %s br0 -d in -a drop -o 7 -r sfilter -p 0:65535 -P 0x%x/0x%x -3 -4",
	       give ? "add" : "del", LANMASK, LANMASK|DF_WANLINK);	/* APNRTL-291 */
}

/* RETURN VALUE
 *      mask indicating a port at which other dhcp server was detected.
 */
static unsigned doit(int sigfd, int found, unsigned char *addr)
{
	int mask = (found) ? port_to_mask(getportbyhaddr(addr)) : 0;
	int signo = (found) ? USIGSTOP : USIGCONT;

	if (found)
		LOG(LOG_INFO, "DHCPD PAUSED [%s %s]", mask_nam(mask), ether_ntoa(addr));
	else
		LOG(LOG_INFO, "DHCPD RESUME");

	if (sigfd != -1)
		send(sigfd, &signo, sizeof(signo), MSG_DONTWAIT);
	sanction(found);
	/* To avoid killall signal, this line was not included sanction. */
	yecho("/proc/sys/net/ipv4/conf/br0/arp_ignore", "%d", found ? 2 : 0);
	return mask;
}

static void exit_probe(int signo)
{
	pidfile_delete("/var/run/udhcpd_probe.pid");
	yexecl(NULL, "aclwrite del br0 -d in -a permit -o 7 -r udp -p 67:67_68:68");
	if (populated)
		sanction(0);
	exit(0);
}

int probe_server_main(const int poll_period_ms, int sigfd)
{
	unsigned int flg, oldflg;
	int pid_fd, fd;
	int last, now, timeout = 0;
	int doprobe;
	unsigned char haddr[6];

	yexecl("2>/dev/null", "iptables -D OUTPUT -o br0 -p 2 -j DROP");
	yexecl(NULL, "aclwrite del br0 -d in -a permit -o 7 -r udp -p 67:67_68:68");

	fd = open("/proc/dvflag", O_RDWR);
	if (fd < 0) {
		perror("/proc/dvflag");
		return -1;
	}

	signal(SIGTERM, exit_probe);

	yexecl(NULL, "aclwrite add br0 -d in -a permit -o 7 -r udp -p 67:67_68:68");

	pid_fd = pidfile_acquire("/var/run/udhcpd_probe.pid");
	pidfile_write_release(pid_fd);

	/* send first probe 10sec later */
	last = monotonic_ms() - 50000;
	flg = LANMASK;
	ioctl(fd, DVFLGIO_SETMASK, &flg);

	for (oldflg = 0;; oldflg = flg) {
		flg = getplugmask(fd, timeout);
		doprobe = 0;

		if (!flg) {	/* All ports are unplugged */
			if (populated)
				populated = doit(sigfd, 0, NULL);
			timeout = -1;
			continue;
		} else if (!(oldflg ^ flg)) {	/* unaltered */
			now = monotonic_ms();
			doprobe = !!((int)(now - last) >= poll_period_ms);
		} else if (!((oldflg ^ flg) & flg)) {	/* unplugged */
			if (populated && !(populated & flg))
				populated = doit(sigfd, 0, NULL);
		} else		/* plugged */
			doprobe = 2;

		if (doprobe) {
			if (doprobe == 2)
				usleep(250000);
			last = monotonic_ms();
			if (poll_server(2000, haddr) < 0) {
				if (populated)
					populated = doit(sigfd, 0, NULL);
			} else {
				if (populated)
					populated |= port_to_mask(getportbyhaddr(haddr));
				else
					populated = doit(sigfd, 1, haddr);
			}
		}

		now = monotonic_ms();
		timeout = poll_period_ms - (int)(now - last);
		if (timeout < 0)
			timeout = 0;
	}

	return 0;
}
