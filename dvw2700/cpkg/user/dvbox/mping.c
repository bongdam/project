#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include "linux_list.h"
#include "dvbox.h"

#define timer_cmp(a, b, CMP)                                            \
  (((a)->tv_sec == (b)->tv_sec) ?                                       \
   (((signed)(a)->tv_usec - (signed)(b)->tv_usec) CMP 0) :              \
   (((signed)(a)->tv_sec - (signed)(b)->tv_sec) CMP 0))

int in_cksum(unsigned short *buf, int sz)
{
	int nleft = sz;
	int sum = 0;
	unsigned short *w = buf;
	unsigned short ans = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *)(&ans) = *(unsigned char *)w;
		sum += ans;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	ans = ~sum;
	return (ans);
}

static int quiet, probe;
static const int DEFDATALEN = 56;
static const int MAXIPLEN = 60;
static const int MAXICMPLEN = 76;
static const int MINDATALEN = 32;
static const int MAXDATALEN = 2048;
#define MAX_DUP_CHK (8 * 128)

struct clockstamp {
	struct timeval tv;
	pid_t pid;
};

struct ping {
	struct list_head list;
	u_int16_t identity;
	struct sockaddr_in addr;
	int datalen;
	long ntransmitted, nreceived, nrepeats, pingcount;
	unsigned long tmin, tmax, tsum;
	char rcvd_tbl[MAX_DUP_CHK / 8];
	struct timeval wait, repwait, reqintvl;
};

#define A(bit)          pong->rcvd_tbl[(bit)>>3]	/* identify byte in array */
#define B(bit)          (1 << ((bit) & 0x07))	/* identify bit in byte */
#define SET(bit)        (A(bit) |= B(bit))
#define CLR(bit)        (A(bit) &= (~B(bit)))
#define TST(bit)        (A(bit) & B(bit))

#undef LOG
#define LOG(pong, fmt, ...) \
	do { \
		if (!quiet) \
			fprintf(stderr, fmt, ##__VA_ARGS__); \
	} while (0)

time_t getcurrenttime(struct timeval *tvp)
{
	struct timespec ts;

	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &ts))
		return (time_t)-1;
	tvp->tv_sec = ts.tv_sec;
	tvp->tv_usec = ts.tv_nsec / 1000;
	return ts.tv_sec;
}

static void timeroff(struct timeval *a, struct timeval *res, time_t off)
{
	*res = *a;
	res->tv_sec += off;
}

static int ping_stats(struct ping *pong)
{
	LOG(pong, "\n--- %s ping statistics ---\n", inet_ntoa(pong->addr.sin_addr));
	LOG(pong, "%ld packets transmitted, ", pong->ntransmitted);
	LOG(pong, "%ld packets received, ", pong->nreceived);
	if (pong->nrepeats)
		LOG(pong, "%ld duplicates, ", pong->nrepeats);
	LOG(pong, "%ld%% packet loss\n",
		(pong->ntransmitted - pong->nreceived) * 100 / pong->ntransmitted);
	if (pong->nreceived)
		LOG(pong, "rtt min/avg/max = %lu.%lu/%lu.%lu/%lu.%lu ms\n",
			pong->tmin / 10,
			pong->tmin % 10,
			(pong->tsum / (pong->nreceived + pong->nrepeats)) / 10,
			(pong->tsum / (pong->nreceived + pong->nrepeats)) % 10,
			pong->tmax / 10, pong->tmax % 10);
	return (pong->nreceived != 0) ? 0 : -1;
}

static struct ping *ping_search(u_int16_t id, struct list_head *head)
{
	struct ping *pong;

	list_for_each_entry(pong, head, list)
		if (pong->identity == id)
			return pong;
	return NULL;
}

static void ping_free(struct ping *pong)
{
	list_del_init(&pong->list);
	if (probe && pong->nreceived > 0)
		printf("%s alive!\n", inet_ntoa(pong->addr.sin_addr));
	if (pong->ntransmitted)
		ping_stats(pong);
	free(pong);
}

static void ping_push_seq(struct ping *pong, struct list_head *head)
{
	struct list_head *pos;

	list_for_each(pos, head) {
		struct ping *p = list_entry(pos, struct ping, list);
		if (timercmp(&pong->repwait, &p->repwait, <) ||
		    timercmp(&pong->reqintvl, &p->reqintvl, <))
			break;
	}
	__list_add(&pong->list, pos->prev, pos);
}

static void ping_flush(struct list_head *head)
{
	struct ping *pong, *t;

	list_for_each_entry_safe(pong, t, head, list)
		ping_free(pong);
}

static char *icmp_type_name(int id)
{
	switch (id) {
	case ICMP_ECHOREPLY:		return "Echo Reply";
	case ICMP_DEST_UNREACH:		return "Destination Unreachable";
	case ICMP_SOURCE_QUENCH:	return "Source Quench";
	case ICMP_REDIRECT:		return "Redirect (change route)";
	case ICMP_ECHO:			return "Echo Request";
	case ICMP_TIME_EXCEEDED:	return "Time Exceeded";
	case ICMP_PARAMETERPROB:	return "Parameter Problem";
	case ICMP_TIMESTAMP:		return "Timestamp Request";
	case ICMP_TIMESTAMPREPLY:	return "Timestamp Reply";
	case ICMP_INFO_REQUEST:		return "Information Request";
	case ICMP_INFO_REPLY:		return "Information Reply";
	case ICMP_ADDRESS:		return "Address Mask Request";
	case ICMP_ADDRESSREPLY:		return "Address Mask Reply";
	default:			return "unknown ICMP type";
	}
}

static struct ping *
ping_recv(int fd, struct list_head *head)
{
	struct timeval tv = {.tv_sec = 1,.tv_usec = 0 };
	char packet[MAXDATALEN + MAXIPLEN + MAXICMPLEN];
	struct icmp *icmppkt;
	struct iphdr *iphdr;
	struct sockaddr_in from;
	socklen_t len;
	int sz, hlen, dupflag;
	struct timeval tnow, ttrip;
	unsigned long triptime;
	struct ping *pong;
	struct clockstamp *ts;

	len = sizeof(from);
	sz = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&from, &len);
	if (sz <= 0)
		return NULL;
	getcurrenttime(&tnow);
	/* check IP header */
	iphdr = (struct iphdr *)packet;
	hlen = iphdr->ihl << 2;
	/* discard if too short */
	if (sz < (hlen + ICMP_MINLEN + sizeof(tnow) + 1))
		return NULL;
	icmppkt = (struct icmp *)&packet[hlen];
	pong = ping_search(icmppkt->icmp_id, head);
	if (pong == NULL)
		return NULL;
	/* convert into cpu order beforehand */
	icmppkt->icmp_seq = ntohs(icmppkt->icmp_seq);
	if (icmppkt->icmp_type == ICMP_ECHOREPLY) {
		ts = (struct clockstamp *)icmppkt->icmp_data;
		if (ts->pid != getpid())
			return NULL;
		++pong->nreceived;
		timersub(&tnow, &ts->tv, &ttrip);
		/* 1/10 msec unit, that is, 100 usec */
		triptime = ttrip.tv_sec * 10000 + ttrip.tv_usec / 100;
		pong->tsum += triptime;
		if (triptime < pong->tmin)
			pong->tmin = triptime;
		if (triptime > pong->tmax)
			pong->tmax = triptime;

		if (TST(icmppkt->icmp_seq % MAX_DUP_CHK)) {
			++pong->nrepeats;
			--pong->nreceived;
			dupflag = 1;
		} else {
			SET(icmppkt->icmp_seq % MAX_DUP_CHK);
			dupflag = 0;
		}

		LOG(pong, "%d bytes from %s: icmp_seq=%u ttl=%d time=%lu.%lu ms%s\n",
		    (sz - ICMP_MINLEN), inet_ntoa(from.sin_addr), icmppkt->icmp_seq,
		    iphdr->ttl, triptime / 10, triptime % 10, (dupflag) ? " (DUP!)" : "");

		if (dupflag == 0) {
			if (--pong->pingcount <= 0 || probe) {
				ping_free(pong);
				return NULL;
			} else {
				timeradd(&tnow, &tv, &pong->reqintvl);
				timeroff(&pong->reqintvl, &pong->repwait, 1);	/* nullifies repwait */
			}
		}
	} else if (icmppkt->icmp_type != ICMP_ECHO)
		LOG(pong, "From %s: icmp_seq=%u %s", inet_ntoa(from.sin_addr),
		    icmppkt->icmp_seq, icmp_type_name(icmppkt->icmp_type));

	return pong;
}

static int ping_send(int fd, struct ping *pong)
{
	char packet[MAXDATALEN + MAXIPLEN + MAXICMPLEN];
	struct icmp *pkt;
	struct clockstamp *ts;
	struct timeval tv = {.tv_sec = 1,.tv_usec = 0 };
	int i;
	u_int16_t seq;

	memset(packet, 0, pong->datalen + 8);
	pkt = (struct icmp *)packet;
	pkt->icmp_type = ICMP_ECHO;
	pkt->icmp_code = 0;
	pkt->icmp_cksum = 0;
	seq = (uint16_t)(pong->ntransmitted + 1);
	pkt->icmp_seq = htons(seq);
	pkt->icmp_id = pong->identity;
	CLR(seq % MAX_DUP_CHK);
	ts = (struct clockstamp *)pkt->icmp_data;
	getcurrenttime(&ts->tv);
	ts->pid = getpid();
	pkt->icmp_cksum = in_cksum((u_int16_t *)pkt, pong->datalen + 8);

	i = sendto(fd, (const void *)pkt, pong->datalen + 8, 0,
		   (struct sockaddr *)&pong->addr, sizeof(struct sockaddr_in));
	if (i < 0)
		LOG(pong, "%s: sendto: %s\n", inet_ntoa(pong->addr.sin_addr), strerror(errno));
	else if ((size_t)i != (pong->datalen + 8))
		LOG(pong, "Wrote %d chars; %d expected\n", i, pong->datalen + 8);
	else {
		pong->ntransmitted++;
		timeradd(&ts->tv, &pong->wait, &pong->repwait);
		timeroff(&pong->repwait, &pong->reqintvl, 1);
		return 0;
	}
	timeradd(&ts->tv, &tv, &pong->reqintvl);
	timeroff(&pong->reqintvl, &pong->repwait, 1);
	return -1;
}

static struct timeval *
ping_do_fsm(int fd, struct list_head *head, struct timeval *tvp)
{
	LIST_HEAD(tmph);
	struct ping *pong, *t;
	struct timeval tv;

	getcurrenttime(&tv);
	list_for_each_entry_safe(pong, t, head, list) {
		if (timer_cmp(&pong->repwait, &tv, <=)) {
			LOG(pong, "Request timed out.\n");
			if (--pong->pingcount <= 0 || ping_send(fd, pong)) {
				ping_free(pong);
				/* have been removed from list chain */
				continue;
			}
		} else if (timer_cmp(&pong->reqintvl, &tv, <=)) {
			if (ping_send(fd, pong)) {
				ping_free(pong);
				continue;
			}
		} else
			break;
		list_del(&pong->list);
		list_add(&pong->list, &tmph);
	}

	list_for_each_entry_safe(pong, t, &tmph, list) {
		list_del(&pong->list);
		ping_push_seq(pong, head);
	}

	if (!list_empty(head)) {
		pong = list_entry(head->next, struct ping, list);
		if (timercmp(&pong->repwait, &pong->reqintvl, <))
			timersub(&pong->repwait, &tv, tvp);
		else
			timersub(&pong->reqintvl, &tv, tvp);
	} else {
		tvp->tv_sec = 0;
		tvp->tv_usec = 0;
	}
	return tvp;
}

static int ping(int fd, struct list_head *head, long count, int datalen, long wait, char *dest, useconds_t usec)
{
	static u_int16_t id;
	struct ping buf;
	struct ping *pong = &buf;
	struct timeval tv;

	if (count < 1)
		return -1;

	memset(pong, 0, sizeof(*pong));
	pong->datalen = datalen;
	pong->pingcount = count;
	pong->tmin = ULONG_MAX;

	pong->addr.sin_addr.s_addr = inet_addr(dest);
	if (pong->addr.sin_addr.s_addr == INADDR_NONE ||
	    pong->addr.sin_addr.s_addr == INADDR_ANY)
		return -1;
	pong->addr.sin_family = AF_INET;
	pong->identity = htons(++id);
	pong->wait.tv_sec = wait / 1000;
	pong->wait.tv_usec = (wait % 1000) * 1000;

	pong = (struct ping *)malloc(sizeof(struct ping));
	memcpy(pong, &buf, sizeof(struct ping));
	if (usec > 0) {
		struct timeval defer =
			{ .tv_sec = usec / 1000000, .tv_usec = usec % 1000000, };
		getcurrenttime(&tv);
		timeradd(&tv, &defer, &pong->reqintvl);
		timeroff(&pong->reqintvl, &pong->repwait, 1);
	} else if (ping_send(fd, pong)) {
		free(pong);
		return -1;
	}
	ping_push_seq(pong, head);
	return 0;
}

static int mping_main(int argc, char **argv)
{
	LIST_HEAD(head);
	int i, fd, opt;
	useconds_t usec, intvlus = 0;
	fd_set rfds, wfds, *pfds;
	struct ping *pong;
	struct timeval timeout, *tvp;
	int count = 4, datalen = DEFDATALEN;
	long wait = 5000;

	while ((opt = getopt(argc, argv, "c:s:w:pqg:")) != -1) {
		switch (opt) {
		case 'c':
			count = atoi(optarg);
			break;
		case 's':
			datalen = atoi(optarg);
			if (datalen < MINDATALEN)
				datalen = MINDATALEN;
			if (datalen > MAXDATALEN)
				datalen = MAXDATALEN;
			break;
		case 'w':
			wait = strtoul(optarg, NULL, 10);
			if (wait < 100)
				wait = 100;
			if (wait > 10000)
				wait = 10000;
			break;
		case 'p':
			probe = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'g':
			intvlus = strtoul(optarg, NULL, 10);
			break;
		default:
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (optind >= argc)
		exit(EXIT_FAILURE);

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) {
		fprintf(stderr, "Socket: %s\n", strerror(errno));
		return -1;
	}
	opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *)&opt, sizeof(opt));
	/* set recv buf for broadcast pings */
	opt = 48 * 1024;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&opt, sizeof(opt));

	for (usec = 0, i = optind; i < argc; usec += intvlus) {
		ping(fd, &head, count, datalen, wait, argv[i++], usec);
		if (intvlus == 0)	/* To receive and send ICMP echo simultaneously */
			break;
	}

	while (!list_empty(&head) || (i < argc)) {
		tvp = ping_do_fsm(fd, &head, &timeout);
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		if (i < argc) {
			FD_ZERO(&wfds);
			FD_SET(fd, &wfds);
			pfds = &wfds;
		} else if (pfds)
			pfds = NULL;
		switch (select(fd + 1, &rfds, pfds, NULL, tvp)) {
		case -1:
			if (errno != EINTR)
				ping_flush(&head);
		case 0:
			break;
		default:
			if (pfds && FD_ISSET(fd, pfds))
				ping(fd, &head, count, datalen, wait, argv[i++], 0);

			if (FD_ISSET(fd, &rfds)) {
				pong = ping_recv(fd, &head);
				if (pong) {
					list_del(&pong->list);
					ping_push_seq(pong, &head);
				}
			}
			break;
		}
	}
	close(fd);
	return 0;
}
REG_APL_LEAF(mping);
