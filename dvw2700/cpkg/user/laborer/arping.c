#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/filter.h>
#include "arping.h"
#include <linux/if_arp.h>
#include "instrument.h"
#include <shutils.h>

struct arpmsg {
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

static void neighbor_free(struct neighbor *);
static void callback(struct neighbor *neigh, int rcode);
static int arping_timeout_callback(long id, long base_id);
static int arping_interval_callback(long id, long base_id);
static LIST_HEAD(neighbors);
static int const_int_1 = 1;

static int iftest(int fd, struct sockaddr_ll *me, const char *device)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr))
		return -1;

	me->sll_ifindex = ifr.ifr_ifindex;
	if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifr))
		return -1;

	if ((ifr.ifr_flags & (IFF_UP|IFF_NOARP|IFF_LOOPBACK)) == IFF_UP)
		return 0;

	errno = ENETUNREACH;
	return -1;
}

static int ifbind(int fd, struct sockaddr_ll *me, in_addr_t dst)
{
	struct sock_filter fcode[] = {
		{0x28, 0, 0, 0x0000000c},	/* (000) ldh  [12]                     */
		{0x15, 0, 5, 0x00000806},	/* (001) jeq  #0x806      jt 2    jf 7 */
		{0x28, 0, 0, 0x00000014},	/* (002) ldh  [20]                     */
		{0x15, 0, 3, 0x00000002},	/* (003) jeq  #0x2        jt 4    jf 7 */
		{0x20, 0, 0, 0x0000001c},	/* (004) ld   [28]                     */
		{0x15, 0, 1, 0x00000000},	/* (005) jeq  #0xXXXXXXXX jt 6    jf 7 */
		{0x6, 0, 0, 0x0000ffff},	/* (006) ret  #65535                   */
		{0x6, 0, 0, 0x00000000},	/* (007) ret  #0                       */
	};
	struct sock_fprog flt = {
		.len = sizeof(fcode) / sizeof(struct sock_filter),
		.filter = fcode,
	};
	socklen_t alen = sizeof(*me);

	//me->sll_ifindex - Must be done before
	me->sll_family = AF_PACKET;
	me->sll_protocol = htons(ETH_P_ARP);
	if (bind(fd, (struct sockaddr *)me, alen) < 0)
		return -1;
	getsockname(fd, (struct sockaddr *)me, &alen);
	fcode[5].k = ntohl(dst);
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &flt, sizeof(flt)) != 0)
		perror("filter");
	return 0;
}

static int ifin_addr(in_addr_t *src, in_addr_t dst, const char *device)
{
	struct ifreq ifr;
	struct sockaddr_in saddr;
	int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
	int nok = -1;

	if (probe_fd < 0)
		return -1;

	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	if (*src) {
		saddr.sin_addr.s_addr = *src;
		nok = bind(probe_fd, (struct sockaddr *)&saddr, sizeof(saddr));
	} else {
		socklen_t alen = sizeof(saddr);

		saddr.sin_port = htons(1025);
		saddr.sin_addr.s_addr = dst;
		if (setsockopt(probe_fd, SOL_SOCKET, SO_DONTROUTE, &const_int_1, sizeof(const_int_1)) == -1)
			perror("setsockopt(SO_DONTROUTE)");
		connect(probe_fd, (struct sockaddr *)&saddr, sizeof(saddr));
		if (getsockname(probe_fd, (struct sockaddr *)&saddr, &alen) == 0
		    && (saddr.sin_family == AF_INET))
			nok = ({ *src = saddr.sin_addr.s_addr; 0; });
	}
	close(probe_fd);
	return nok;
}

static int send_pack(int fd, struct sockaddr_ll *me, struct sockaddr_ll *he,
                     struct in_addr src, struct in_addr dst)
{
	char buf[sizeof(struct arpmsg)] = { 0 };
	struct arpmsg *pack = (struct arpmsg *)buf;

	memcpy(pack->ethhdr.h_dest, he->sll_addr, 6);
	memcpy(pack->ethhdr.h_source, me->sll_addr, 6);
	pack->ethhdr.h_proto = htons(ETH_P_ARP);

	pack->htype = htons(ARPHRD_ETHER);
	pack->ptype = htons(ETH_P_IP);
	pack->hlen = 6;
	pack->plen = 4;
	pack->operation = htons(ARPOP_REQUEST);
	memcpy(pack->sInaddr, &src, 4);
	memcpy(pack->sHaddr, me->sll_addr, 6);
	if ((he->sll_addr[0] & 0x01) == 0)
		memcpy(pack->tHaddr, he->sll_addr, 6);
	memcpy(pack->tInaddr, &dst, 4);

	return sendto(fd, pack, sizeof(struct arpmsg), 0,
	              (struct sockaddr *)he, sizeof(*he));
}

#define arpong_fdset select_event_fdset_dfl

static int arpong_read(struct select_event_base *base, int fd)
{
	struct neighbor *neigh = (struct neighbor *)base->data;
	struct arpmsg repl;
	int n;

	n = recv(fd, &repl, sizeof(repl), 0);
	if (n <= 0 || repl.operation != htons(ARPOP_REPLY))
		return n;

	if (!(neigh->copt & DAD)) {
		if (memcmp(&neigh->src, repl.tInaddr, sizeof(repl.plen)) ||
		    memcmp(neigh->me.sll_addr, repl.tHaddr, repl.hlen))
			return n;
	} else {
		if (!memcmp(repl.sHaddr, neigh->me.sll_addr, neigh->me.sll_halen) ||
		    (neigh->src.s_addr && memcmp(&neigh->src, repl.tInaddr, sizeof(repl.plen))))
			return n;
	}
	/* replied! close socket immediately */
	memcpy(neigh->he.sll_addr, repl.sHaddr, neigh->he.sll_halen);
	callback(neigh, 1);
	return 0;
}

static int arpong_close(struct select_event_base *base, int fd)
{
	neighbor_free((struct neighbor *)base->data);
	base->fd = -1;	/* be careful not to free twice */
	return 0;
}

static struct select_event_operation arping_op = {
	._fdset = arpong_fdset,
	._read = arpong_read,
	._close = arpong_close,
};

static void callback(struct neighbor *neigh, int rcode)
{
	int saved_errno = errno;
	char buf[18];

	if (neigh->cb)
		neigh->cb(neigh, rcode);

	neigh->cb = NULL;	/* must not be invoked again in neigh_free */

	if (neigh->script)
		yexecl(NULL, "%s %s %s %d %d", neigh->script,
		       inet_ntoa(neigh->dst),
		       ether_etoa(neigh->he.sll_addr, buf),
		       rcode, (rcode < 0) ? saved_errno : 0);

	free(neigh->script);
	neigh->script = NULL;
}

long schedule(unsigned long data,
              int (*func)(long, unsigned long), int timeout)
{
	struct timeval tv = {
		.tv_sec = timeout / 1000,
		.tv_usec = (timeout % 1000) * 1000,
	};
	return itimer_creat(data, func, &tv);
}

static int arping_timeout_callback(long id, long base_id)
{
	struct select_event_base *base = select_event_getbyid(base_id);
	struct neighbor *neigh;

	if (base == NULL)
		return 0;

	neigh = (struct neighbor *)base->data;
	if (neigh->transmit > 0)
		neigh->transmit--;

	if (!neigh->transmit) {
		callback(neigh, 0);
		select_event_free(base);
	} else
		neigh->tid = schedule(base_id, (void *)arping_interval_callback,
		                      neigh->interval - neigh->timeout);
	return 0;
}

static int arping_interval_callback(long id, long base_id)
{
	struct select_event_base *base = select_event_getbyid(base_id);
	if (base) {
		struct neighbor *neigh = (struct neighbor *)base->data;
		send_pack(neigh->fd, &neigh->me, &neigh->he, neigh->src, neigh->dst);
		neigh->tid = schedule(base_id,
		                      (void *)arping_timeout_callback, neigh->timeout);
	}
	return 0;
}

static void neighbor_free(struct neighbor *neigh)
{
	if (!list_empty(&neigh->list))
		list_del(&neigh->list);

	if (neigh->fd > -1)
		close(neigh->fd);

	if (neigh->tid)
		itimer_cancel(neigh->tid, NULL);

	callback(neigh, -1);
	free(neigh->script);
	free(neigh);
}

static struct neighbor *neigh_search_ia(struct list_head *h, in_addr_t ip)
{
	struct neighbor *neigh;

	list_for_each_entry(neigh, h, list)
		if (neigh->dst.s_addr == ip)
			return neigh;
	return NULL;
}

static int neigh_lookup(int s, in_addr_t tina, u_char thwa[ETH_ALEN], const char *ifname)
{
	struct arpreq ar;
	struct sockaddr_in *sin;

	memset(&ar, 0, sizeof(ar));
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = tina;
	strlcpy(ar.arp_dev, ifname, sizeof(ar.arp_dev));

	if (ioctl(s, SIOCGARP, (caddr_t)&ar) == 0) {
		if (ar.arp_flags & ATF_COM) {
			memcpy(thwa, ar.arp_ha.sa_data, ETH_ALEN);
			return 0;
		}
	}
	return -1;
}

static struct neighbor *
neigh_list_add(struct list_head *h,
               in_addr_t src, in_addr_t dst,
               const char *device,
               int transmit,
               int timeout, int interval,
               char *script,
               unsigned int copt)
{
	struct neighbor *neigh = neigh_search_ia(h, dst);
	struct select_event_base *base;

	if (neigh)
		return neigh;

	if (timeout <= 0)
		timeout = 100;

	if (interval < timeout)
		interval = timeout;

	neigh = (struct neighbor *)calloc(sizeof(*neigh), 1);
	if (neigh == NULL)
		return NULL;
	INIT_LIST_HEAD(&neigh->list);
	neigh->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (neigh->fd < 0)
		goto out;
	else if (iftest(neigh->fd, &neigh->me, device))
		goto out;
	else if (ifbind(neigh->fd, &neigh->me, dst))
		goto out;

	if (!(copt & DAD) || src) {
		if ((!src || (copt & STRICT)) && ifin_addr(&src, dst, device))
			goto out;
	}

	neigh->he = neigh->me;
	if (!(copt & UNICASTING) || neigh_lookup(neigh->fd, dst, neigh->he.sll_addr, device))
		memset(neigh->he.sll_addr, -1, neigh->he.sll_halen);

	neigh->src.s_addr = src;
	neigh->dst.s_addr = dst;
	neigh->transmit = transmit;
	neigh->timeout = timeout;
	neigh->interval = interval;
	neigh->copt = copt;

	base = select_event_alloc(neigh->fd, &arping_op,
	                          neigh, "socket://raw/arping/%s", inet_ntoa(neigh->dst));
	if (base) {
		neigh->script = script ? strdup(script) : NULL;
		send_pack(neigh->fd, &neigh->me, &neigh->he, neigh->src, neigh->dst);
		neigh->tid = schedule(base->id, (void *)arping_timeout_callback, timeout);
		list_add(&neigh->list, h);
		return neigh;
	}
out:
	neighbor_free(neigh);
	return NULL;
}

/*
Options:
	-c N            Send N ARP requests till got replied
	-w timeout      Time to wait for ARP reply, in ms
	-i interval     Wait interval ms between sending each packet
	-I dev          Interface to use (default eth0)
	-s sender       Sender IP address
	-S script       Script to be executed on
	-u              Unicast if resolved already
	-D              Duplicated address detection mode
	-t              Strictly test sender ip specified
	target          Target IP address
 */
struct neighbor *arping_main(int argc, char **argv, int fd)
{
	int transmit = 1;
	int timeout = 500;
	int interval = 1000;
	int opt;
	char dev[16] = { [0] = '\0' };
	char *script = NULL;
	in_addr_t src = INADDR_ANY;
	unsigned int copt = 0;
	struct neighbor *neigh = NULL;

	optind = 0;	/* reset to 0, rather than the traditional value of 1 */
	while ((opt = getopt(argc, argv, "c:w:i:I:s:S:uDt")) != -1) {
		switch (opt) {
		case 'w':
			timeout = strtol(optarg, NULL, 0);
			break;
		case 'i':
			interval = strtol(optarg, NULL, 0);
			break;
		case 'I':
			strlcpy(dev, optarg, sizeof(dev));
			break;
		case 's':
			src = inet_addr(optarg);
			break;
		case 'S':
			script = alloca(strlen(optarg) + 1);
			strcpy(script, optarg);
			break;
		case 'D':
			copt |= DAD;
			break;
		case 'u':
			copt |= UNICASTING;
			break;
		case 't':
			copt |= STRICT;
			break;
		case 'c':
			transmit = strtol(optarg, NULL, 0);
			if (transmit)
				break;
		default:
			if (fd > -1)
				dprintf(fd, "Invalid option\n");
			return NULL;
		}
	}

	if (dev[0] != '\0' && (optind < argc)) {
		neigh = neigh_list_add(&neighbors, src,
		                       inet_addr(argv[optind]), dev,
		                       transmit, timeout, interval, script, copt);
		if (!neigh)
			dprintf(fd, "%s: %m\n", argv[0]);
	} else if (fd > -1)
		dprintf(fd, "'%s' not specified\n", dev[0] ? "target" : "interface");

	return neigh;
}

static int mod_arping(int argc, char **argv, int fd)
{
	return arping_main(argc, argv, fd) ? 0 : 1;
}

static void __attribute__((constructor)) register_arping_module(void)
{
	fifo_cmd_register("arping",
	                  "\t[-c count] [-w timeout] [-i interval] [-I dev] [-s sender] [-S script] [-u] [-D] target",
	                  "ARP ping", mod_arping);
}
