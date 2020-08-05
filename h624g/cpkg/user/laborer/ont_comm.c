#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <features.h>
#if __GLIBC__ >=2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <linux/filter.h>
#include <errno.h>
#include <endian.h>
#include <time.h>

#include <libytool.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "instrument.h"
#include "cmd.h"

//#define _NDEBUG	1

#ifndef _NDEBUG
#define DIAG(arg...) \
	do {\
		if (verbose) \
			diag_printf(arg);\
	} while (0)
#else
#define DIAG(arg...) do {} while (0)
#endif

#define PROBE_INTV	500

unsigned int if_nametoindex(const char *ifname);
void getcurrenttime(struct timeval *tvp);

#if defined(__BIG_ENDIAN__) || (__BYTE_ORDER == __BIG_ENDIAN)
static const u_int32_t _magicKey = 0x47504F4E;
#else
static const u_int32_t _magicKey = 0x4E4F5047;
#endif
static const u_int16_t _serverPort = 5874;

enum {
	EBADVER = 800,
	EXID,
	ELENGTH,
	EBADTLV,
	E2SHORT,
	ETRUNCATE,
	EBOGUS,
	ECKSUM,
	EMAGIC
};

enum {
	CRESPONSE = 1,
	CPOLLREQ,
	CSETREQ,
	CGETREQ,
	CTERMREQ
};

enum {
	TRESULT = 1,
	TTERMCAUSE,
	TSERIALNO,
	TVERSION,
	TRXPOWER,
	TNETADDRESS,
	TLASER
};

struct tmsgtlv {
	u_int16_t type;
	u_int16_t len;
	char value[0];
};

struct tmsghdr {
	u_int32_t magic;
	u_int8_t version;
	u_int8_t flag;
	u_int16_t reserved;
	u_int16_t xid;
	u_int16_t code;
	struct tmsgtlv tlv[0];
};

struct udp_tmsg_packet {
	struct iphdr ip;
	struct udphdr udp;
	struct tmsghdr tmsgh;
};

enum {
	EIDLE,
	EPOLL1, EPOLL2, EPOLL3, EPOLL4,	/* Must be a row */
	ERUN
};

enum {
	EREAD,
	EEXPIRED,
	ECANCEL,
	EWRITE
};

enum {
	TIMER0,
	TIMER2,
	TIMER3,
	TIMER4
};

struct request {
	struct tmsghdr *msg;
	size_t msglen;
	int xmits;
	struct timeval expiry;
	char pipenam[80];
};

#define timeout_set(res, a, s, us) \
  do {\
	struct timeval __tv = { .tv_sec = (s),\
				.tv_usec = (us) };\
	timeradd(&(a), &__tv, &(res));\
  } while (0)

static const char *terror(int errnr);
static struct udp_tmsg_packet *build_probe(u_int16_t source_port, u_int16_t dest_port);
static int fsm_timeout(long id, unsigned long arg);
static int raw_socket(int, u_int16_t, struct sockaddr_ll *);
static int verify_tmsg(u_int16_t xid, struct tmsghdr *res, int len);
static int recv_raw_tmsg(struct udp_tmsg_packet *packet, size_t n, ushort toport, int fd);
static int connect_channel(const char *ifname, struct in6_addr *i6, u_int16_t toport);
#ifndef _NDEBUG
static void raw_dump(u_char *p, unsigned int s, u_char *base, const char *fmt, ...);
#endif

#define abort_request(r, arg...)	end_request(r, 1, arg)

#ifndef _NDEBUG
static int verbose;
#endif
static char interface[IFNAMSIZ];
static long tid[TIMER4 + 1];
static int fstate = EIDLE;
static int _fd = -1;
static struct udp_tmsg_packet *probe = NULL;
static struct sockaddr_ll sll;
static struct in6_addr peer6;
static struct request *_req;

#ifndef _NDEBUG
static void diag_printf(const char *format, ...)
{
	va_list ap;
	struct timeval now;
	struct tm *ptm;

	gettimeofday(&now, NULL);
	ptm = localtime(&now.tv_sec);
	fprintf(stdout, "[%02d:%02d:%02d.%03ld] ",
		ptm->tm_hour, ptm->tm_min, ptm->tm_sec, now.tv_usec / 1000);
	va_start(ap, format);
	vfprintf(stdout, format, ap);
	va_end(ap);
}
#endif

static const char *in_ntop(int af, const void *src)
{
	static char str[INET6_ADDRSTRLEN];
	return inet_ntop(af, src, str, sizeof(str));
}

static void safe_free(void **ptr)
{
	void *p;

	if (ptr && (p = *ptr)) {
		*ptr = NULL;
		free(p);
	}
}

static void safe_close(int *pfd)
{
	int fd;

	if (pfd && (fd = *pfd) > -1) {
		*pfd = -1;
		close(fd);
	}
}

static int stop_timer(int i)
{
	int status = -1;
	if ((i < _countof(tid)) && tid[i]) {
		status = itimer_cancel(tid[i], NULL);
		tid[i] = 0;
	}
	return status;
}

static int start_timer(int i, struct request *req, int (*func)(long, unsigned long))
{
	struct timeval timeout = { .tv_usec = 0 };

	stop_timer(i);
	switch (i) {
	case TIMER0:
		timeout.tv_sec = 2;
		break;
	case TIMER2:
	case TIMER3:
		timeout.tv_sec = 2;
		break;
	case TIMER4:
		timeout.tv_sec = 3600;
		break;
	default:
		return -1;
	}

	tid[i] = itimer_creat((u_long)req, func, &timeout);
	return 0;
}

static int sys_operate_ip6(int on)
{
	if (strcmp(interface, "eth1"))
		return 0;
	if (!nvram_match("CUSTOM_PASSTHRU_ENABLED", "0"))
		return 0;
	DIAG("/proc/sys/net/ipv6/conf/eth1/disable_ipv6 %d\n", !on);
	return yecho("/proc/sys/net/ipv6/conf/eth1/disable_ipv6", "%d", !on);
}

static int end_request(struct request *req, int rst, const char *fmt, ...)
{
	int i;

	if (req) {
		int fd = open_reply_pipe(req->pipenam);
		if (fd > -1) {
			va_list args;
#ifndef _NDEBUG
			va_list aq;
#endif
			va_start(args, fmt);
#ifndef _NDEBUG
			va_copy(aq, args);
			vfprintf(stderr, fmt, aq);
			va_end(aq);
#endif
			vdprintf(fd, fmt, args);
			va_end(args);
			close(fd);
		} else
			DIAG("%s: %s %s\n", __func__, req->pipenam, strerror(errno));
		free(req->msg);
		free(req);
		if (req == _req)
			_req = NULL;
	}

	if (rst) {
		safe_free((void **)&probe);
		safe_close(&_fd);
		fstate = EIDLE;
		for (i = 0; i < _countof(tid); i++)
			stop_timer(i);
		sys_operate_ip6(0);
	}
	return 0;
}

static const char *stringify_tlv(struct tmsgtlv *tlv, int len)
{
	static char *p = NULL;
	static char buf[INET6_ADDRSTRLEN];

	if (len <= 0)
		return "Empty TLV";

	switch (ntohs(tlv->type)) {
	case TRESULT:
		snprintf(buf, sizeof(buf), "Error code %d", tlv->value[0]);
		break;
	case TTERMCAUSE:
		snprintf(buf, sizeof(buf), "Termination cause %d", tlv->value[0]);
		break;
	case TSERIALNO:
	case TVERSION:
	case TRXPOWER:
		if (ntohs(tlv->len) < sizeof(buf))
			sprintf(buf, "%.*s", ntohs(tlv->len), tlv->value);
		else if ((p = realloc(p, ntohs(tlv->len) + 1))) {
			sprintf(p, "%.*s", ntohs(tlv->len), tlv->value);
			return p;
		}
		break;
	case TNETADDRESS:
		return in_ntop(ntohs(tlv->len) == 16 ? AF_INET6 : AF_INET, tlv->value);
	case TLASER:
		snprintf(buf, sizeof(buf), "Laser %s", tlv->value[0] ? "on" : "off");
		break;
	default:
		snprintf(buf, sizeof(buf), "Unknown %d type with %d length", ntohs(tlv->type), ntohs(tlv->len));
		break;
	}

	return buf;
}

#ifndef _NDEBUG
static const char *event_name(int event)
{
	switch (event) {
	case EREAD:
		return "READ";
	case EEXPIRED:
		return "EXPIRED";
	case ECANCEL:
		return "CANCEL";
	case EWRITE:
		return "WRITE";
	default:
		return "Unknown";
	}
}

static const char *state_name(int state)
{
	switch (state) {
	case EIDLE:
		return "INIT";
	case EPOLL1:
		return "POLL1";
	case EPOLL2:
		return "POLL2";
	case EPOLL3:
		return "POLL3";
	case EPOLL4:
		return "POLL4";
	case ERUN:
		return "RUN";
	default:
		return "Unknown";
	}
}
#endif

static int fsm_transit(int event, struct request *req)
{
	char buf[sizeof(struct udp_tmsg_packet) + 1024];
	struct udp_tmsg_packet *packet;
	struct tmsghdr *tmsgh;
	struct tmsgtlv *tlv = NULL;
	struct timeval current, rexmit;
	struct timeval timeout;
	int n, status;

	DIAG("%s in %s state (req: %#x)\n", event_name(event), state_name(fstate), req);

	switch (event) {
	case EREAD:
		switch (fstate) {
		case EIDLE:
			break;
		case EPOLL1:
		case EPOLL2:
		case EPOLL3:
		case EPOLL4:
			packet = (struct udp_tmsg_packet *)buf;
			n = recv_raw_tmsg(packet, sizeof(buf), _serverPort, _fd);
			if (n > 0) {
				status = verify_tmsg(probe->tmsgh.xid, &packet->tmsgh, n);
				if (status < 0)
					DIAG("verify_tmsg: %s\n", terror(status));
				else {
					if (n <= sizeof(struct tmsghdr) ||
					    (({ tlv = &packet->tmsgh.tlv[0]; 1;}) && ntohs(tlv->type) != TNETADDRESS))
						return abort_request(req, "%s\n", tlv ?
							stringify_tlv(tlv, n - sizeof(struct tmsghdr))
							: "Network address not found");

					if (ntohs(tlv->len) != sizeof(struct in6_addr))
						return abort_request(req, "Supported only IPv6 address\n");

					if (IN6_IS_ADDR_LOOPBACK(tlv->value) || IN6_IS_ADDR_UNSPECIFIED(tlv->value))
						return abort_request(req, "Invalid IPv6 address\n");

					memcpy(&peer6, tlv->value, sizeof(peer6));
					safe_free((void **)&probe);
					stop_timer(TIMER2);
					/* setup channel for the RUN state */
					safe_close(&_fd);
					sys_operate_ip6(1);
					fstate = ERUN;
					start_timer(TIMER0, req, fsm_timeout);
				}
			} else
				DIAG("recv_raw_tmsg: %s\n", terror(n));
			break;
		case ERUN:
			if (_fd < 0)
				break;
			tmsgh = (struct tmsghdr *)buf;
			n = recv(_fd, buf, sizeof(buf), 0);
			if (n <= 0) {
				if (errno == ECONNREFUSED && req->xmits < 2) {
					end_request(NULL, 1, NULL);
					timeout.tv_sec = 0;
					timeout.tv_usec = 100000;
					tid[TIMER0] = itimer_creat((u_long)req, fsm_timeout, &timeout);
					break;
				} else
					return abort_request(req, "%s\n", strerror(errno));
			}
			status = verify_tmsg(req->msg->xid, tmsgh, n);
			if (status < 0)
				return abort_request(req, "%s\n", strerror(status));
			else {
				stop_timer(TIMER3);
				start_timer(TIMER4, NULL, fsm_timeout);
				return end_request(req, 0, "%s\n",
					stringify_tlv(tmsgh->tlv, n - sizeof(struct tmsghdr)));
			}
			break;
		}
		break;

	case EWRITE:
		if (fstate == ERUN) {
			if (_fd < 0) {
				_fd = connect_channel(interface, &peer6, _serverPort);
				if (_fd < 0)
					return abort_request(req, "Cannot connect channel: %s\n",
							(_fd < -1) ? gai_strerror(_fd) : strerror(errno));
			}
			if (tid[TIMER0] || tid[TIMER3])
				return end_request(req, 0, "Previous request ongoing\n");
#ifndef _NDEBUG
			if (verbose)
				raw_dump((u_char *)req->msg, req->msglen, (u_char *)req->msg,
					"sending code %d xid %04x\n", ntohs(req->msg->code), ntohs(req->msg->xid));
#endif
			n = send(_fd, req->msg, req->msglen, 0);
			if (n != req->msglen)
				return abort_request(req, "%s\n", strerror(errno));
			req->xmits++;
			start_timer(TIMER3, req, fsm_timeout);
			break;
		} else if (fstate == EIDLE && !tid[TIMER0]) {
			_fd = raw_socket(if_nametoindex(interface), _serverPort, &sll);
			if (_fd < 0)
				return abort_request(req, "%s\n", strerror(errno));
			probe = build_probe(_serverPort, _serverPort);
			if (probe == NULL)
				return abort_request(req, "%s\n", strerror(errno));
			fstate = EPOLL1;
			/* fake event */
			event = EEXPIRED;
		} else
			return end_request(req, 0, "Previous request ongoing\n");
		/* fall through */

	case EEXPIRED:
		switch (fstate) {
		case EIDLE:
			break;
		case EPOLL1:
		case EPOLL2:
		case EPOLL3:
			getcurrenttime(&current);
			if (fstate < EPOLL3)
				timeout_set(rexmit, current, 0, PROBE_INTV * 1000);
			else
				rexmit = req->expiry;

			if (!timercmp(&rexmit, &req->expiry, >)) {
				sll.sll_halen = ETH_ALEN;
				memcpy(sll.sll_addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN);
#ifndef _NDEBUG
				if (verbose)
					raw_dump((u_char *)&probe->tmsgh, ntohs(probe->udp.len) - sizeof(probe->udp), (u_char *)&probe->tmsgh,
						"probing code %d xid %04x\n", ntohs(probe->tmsgh.code), ntohs(probe->tmsgh.xid));
#endif
				n = sendto(_fd, probe, ntohs(probe->ip.tot_len), 0,
						(struct sockaddr *)&sll, sizeof(sll));
				if (n < 0)
					return abort_request(req, "%s\n", strerror(errno));
				timersub(&rexmit, &current, &timeout);
				tid[TIMER2] = itimer_creat((u_long)req, fsm_timeout, &timeout);
				fstate += 1;
				break;
			}
		/* fall through */
		case EPOLL4:
		case ERUN:
			return abort_request(req, "Request timed out!\n");
		}
		break;
	case ECANCEL:
		return abort_request(NULL, "Request aborted\n");
	}

	return 0;
}

static int fsm_timeout(long id, unsigned long arg)
{
	int i, event;

	for (i = 0; i < _countof(tid) && tid[i] != id; i++) {}
	switch (i) {
	case TIMER0:
		event = EWRITE;
		break;
	case TIMER2:
	case TIMER3:
		event = EEXPIRED;
		break;
	case TIMER4:
		event = ECANCEL;
		break;
	default:
		return 0;
	}

	tid[i] = 0;

	fsm_transit(event, (struct request *)arg);
	return 0;
}

static const char *terror(int errnr)
{
	if (errnr < 0)
		errnr = 0 - errnr;

	switch (errnr) {
	case EBADVER:
		return "Unsupported version";
	case EXID:
		return "Transaction id mismatch";
	case ELENGTH:
		return "Invalid total length";
	case EBADTLV:
		return "Bad TLV";
	case E2SHORT:
		return "Message too short";
	case ETRUNCATE:
		return "Truncated message";
	case EBOGUS:
		return "Bogus packet";
	case ECKSUM:
		return "Incorrect checksum";
	case EMAGIC:
		return "Invalid key";
	default:
		return strerror(errnr);
	}
}

static int connect_channel(const char *ifname, struct in6_addr *i6, u_int16_t toport)
{
	char node[INET6_ADDRSTRLEN + IFNAMSIZ + 1], service[8];
	const char *p;
	struct addrinfo *res = NULL;
	struct addrinfo hint;
	int fd;

	if ((p = in_ntop(AF_INET6, i6)) == NULL)
		return -1;

	snprintf(node, sizeof(node), "%s%%%s", p, ifname);
	sprintf(service, "%u", toport);

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET6;
	hint.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(node, service, &hint, &res) || !res)
		return -2;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd > -1) {
		if (connect(fd, (struct sockaddr *)res->ai_addr, res->ai_addrlen)) {
			close(fd);
			fd = -1;
		}
	}
	freeaddrinfo(res);
	return fd;
}

static u_int16_t checksum(void *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 */
	register int32_t sum = 0;
	u_int16_t *source;

	for (source = (u_int16_t *)addr; count > 1; count -= 2)
		sum += *source++;
	/*  Add left-over byte, if any */
	if (count > 0) {
		/* Make sure that the left-over byte is added correctly both
		 * with little and big endian hosts */
		u_int16_t tmp = 0;
		*(u_int8_t *)(&tmp) = *(u_int8_t *)source;
		sum += tmp;
	}

	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static int raw_socket(int ifindex, u_int16_t source_port, struct sockaddr_ll *sock)
{
	int fd;
	struct sock_fprog fprog;
	struct sock_filter fcode[] = {
		{ 0x30, 0, 0, 0x00000009 },     /* (000) ldb      [9]                           */
		{ 0x15, 0, 6, 0x00000011 },     /* (001) jeq      #0x11            jt 2    jf 8 */
		{ 0x28, 0, 0, 0x00000006 },     /* (002) ldh      [6]                           */
		{ 0x45, 4, 0, 0x00001fff },     /* (003) jset     #0x1fff          jt 8    jf 4 */
		{ 0xb1, 0, 0, 0x00000000 },     /* (004) ldxb     4*([0]&0xf)                   */
		{ 0x48, 0, 0, 0x00000000 },     /* (005) ldh      [x]                           */
		{ 0x15, 0, 1, source_port},     /* (006) jeq      #0x16f2          jt 7    jf 8 */
		{ 0x6,  0, 0, 0x0000ffff },     /* (007) ret      #65535                        */
		{ 0x6,  0, 0, 0x00000000 }      /* (008) ret      #0                            */
	};

	DIAG("opening raw socket on ifindex %d\n", ifindex);
	if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0) {
		DIAG("socket call failed: %s\n", strerror(errno));
		return -1;
	}

	sock->sll_family = AF_PACKET;
	sock->sll_protocol = htons(ETH_P_IP);
	sock->sll_ifindex = ifindex;
	if (bind(fd, (struct sockaddr *)sock, sizeof(*sock)) < 0) {
		DIAG("bind call failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	fprog.len = sizeof(fcode) / sizeof(struct sock_filter);
	fprog.filter = fcode;
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &fprog, sizeof(fprog)) != 0)
		perror("so_attach_filter");

	return fd;
}

static struct udp_tmsg_packet *
build_probe(u_int16_t source_port, u_int16_t dest_port)
{
	struct udp_tmsg_packet *packet;
	int len;

	len = sizeof(struct udp_tmsg_packet);
	packet = (struct udp_tmsg_packet *)calloc((len < 64) ? 64 : len, 1);
	if (packet == NULL)
		return NULL;

	packet->ip.protocol = IPPROTO_UDP;
	packet->ip.daddr = INADDR_BROADCAST;
	packet->udp.source = htons(source_port);
	packet->udp.dest = htons(dest_port);
	packet->udp.len = htons(sizeof(packet->udp) + sizeof(struct tmsghdr));	/* cheat on the psuedo-header */
	packet->ip.tot_len = packet->udp.len;

	packet->tmsgh.magic = _magicKey;
	packet->tmsgh.version = 1;
	packet->tmsgh.xid = rand();
	packet->tmsgh.code = htons(CPOLLREQ);
	packet->udp.check = checksum(packet, len);

	packet->ip.tot_len = htons(len);
	packet->ip.ihl = sizeof(packet->ip) >> 2;
	packet->ip.version = IPVERSION;
	packet->ip.ttl = IPDEFTTL;
	packet->ip.check = checksum(&(packet->ip), sizeof(packet->ip));

	return packet;
}

#ifndef _NDEBUG
static void raw_dump(u_char *p, unsigned int s, u_char *base, const char *fmt, ...)
{
	int i, c;
	va_list args;

	if (fmt) {
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
	}

	while ((int)s > 0) {
		printf("%08x: ", (unsigned int)base);

		for (i = 0; i < 16; i++) {
			if (i < (int)s)
				printf("%02x ", p[i] & 0xFF);
			else
				printf("   ");

			if (i == 7)
				printf(" ");
		}
		printf(" |");
		for (i = 0; i < 16; i++) {
			if (i < (int)s) {
				c = p[i] & 0xFF;
				if ((c < 0x20) || (c >= 0x7F))
					c = '.';
			} else
				c = ' ';

			printf("%c", c);
		}
		printf("|\n");
		s -= 16;
		p += 16;
		base += 16;
	}
}
#endif

static int verify_tmsg(u_int16_t xid, struct tmsghdr *res, int len)
{
	int i, tot_len;
	u_char *p;
	u_int16_t tlvsiz;

#ifndef _NDEBUG
	if (verbose)
		raw_dump((u_char *)res, len, (u_char *)res,
			"received code %d xid %04x\n", ntohs(res->code), ntohs(res->xid));
#endif
	if (res->magic != _magicKey)
		return -EMAGIC;
	if (res->version != 1)
		return -EBADVER;
	if (xid != res->xid)
		return -EXID;
	if (len < sizeof(struct tmsghdr))
		return -ELENGTH;

	p = (u_char *)&res[1];
	tot_len = len - sizeof(struct tmsghdr);

	for (i = 0; i < tot_len; p = &p[i]) {
		if ((i + 4) > tot_len)
			return -EBADTLV;
		tlvsiz = p[2] << 8;
		tlvsiz += p[3];
		i += (4 + tlvsiz);
	}

	return (i == tot_len) ? 0 : -EBADTLV;
}

static int recv_raw_tmsg(struct udp_tmsg_packet *packet, size_t n, ushort toport, int fd)
{
	int bytes;
	u_int32_t source, dest;
	u_int16_t check;

	memset(packet, 0, sizeof(struct udp_tmsg_packet));
	bytes = read(fd, packet, n);
	if (bytes < 0)
		return -errno;

	if (bytes < (int)(sizeof(struct iphdr) + sizeof(struct udphdr)))
		return -E2SHORT;

	if (bytes < (int)ntohs(packet->ip.tot_len))
		return -ETRUNCATE;

	/* ignore any extra garbage bytes */
	bytes = ntohs(packet->ip.tot_len);

	/* Make sure its the right packet for us, and that it passes sanity checks */
	if (packet->ip.protocol != IPPROTO_UDP ||
	    packet->ip.version != IPVERSION ||
	    packet->ip.ihl != sizeof(packet->ip) >> 2 ||
	    packet->udp.dest != htons(toport) ||
	    ntohs(packet->udp.len) != (uint16_t)(bytes - sizeof(packet->ip)))
		return -EBOGUS;

	/* check IP checksum */
	check = packet->ip.check;
	packet->ip.check = 0;
	if (check != checksum(&(packet->ip), sizeof(packet->ip)))
		return -ECKSUM;

	/* verify the UDP checksum by replacing the header with a psuedo header */
	source = packet->ip.saddr;
	dest = packet->ip.daddr;
	check = packet->udp.check;
	packet->udp.check = 0;
	memset(&packet->ip, 0, sizeof(packet->ip));

	packet->ip.protocol = IPPROTO_UDP;
	packet->ip.saddr = source;
	packet->ip.daddr = dest;
	packet->ip.tot_len = packet->udp.len;	/* cheat on the psuedo-header */
	if (check && check != checksum(packet, bytes))
		return -ECKSUM;

	return bytes - (sizeof(packet->ip) + sizeof(packet->udp));
}

static struct request *
build_req(u_int16_t code, u_int16_t type, u_int16_t len, const void *value, char *response_pipe)
{
	struct request *req;
	struct timeval current;

	if (_req) {
		errno = EBUSY;
		return NULL;
	}

	req = malloc(sizeof(struct request));
	if (req != NULL) {
		req->msglen = sizeof(struct tmsghdr) + sizeof(struct tmsgtlv) + len;
		req->msg = calloc(req->msglen, 1);
		req->xmits = 0;
		if (req->msg) {
			snprintf(req->pipenam, sizeof(req->pipenam), "%s", response_pipe);
			req->msg->magic = _magicKey;
			req->msg->version = 1;
			req->msg->xid = rand();
			req->msg->code = htons(code);
			req->msg->tlv[0].type = htons(type);
			req->msg->tlv[0].len = htons(len);
			if (len > 0)
				memcpy(req->msg->tlv[0].value, value, len);
			getcurrenttime(&current);
			timeout_set(req->expiry, current, 2, 0);
			_req = req;
			fsm_transit(EWRITE, req);
		} else
			safe_free((void **)&req);
	}
	return req;
}

#define onoff(s)	(!strcasecmp((s), "on") || !strcmp((s), "1"))
static int post_request(int argc, char **argv, char *response_pipe)
{
	/*
	 * ont set serial 123456789
	 * ont get serial
	 * ont get version
	 * ont get rxpwr
	 * ont quit
	 * ont verbose [01]
	 */
	struct request *req = (struct request *)0xdeadbeef;
	char opt;
	enum { EUNIMPL = 1, EFEWARG };
	int status = EUNIMPL;

	if (argc > 1) {
		if (!strcmp("set", argv[1])) {
			if (argc < 4)
				status = EFEWARG;
			else if (!strcmp(argv[2], "serial"))
				req = build_req(CSETREQ, TSERIALNO, strlen(argv[3]) + 1, argv[3], response_pipe);
			else if (!strcmp(argv[2], "laser")) {
				opt = onoff(argv[3]);
				req = build_req(CSETREQ, TLASER, 1, &opt, response_pipe);
			}
		} else if (!strcmp("get", argv[1])) {
			if (argc < 3)
				status = EFEWARG;
			else if (!strcmp("serial", argv[2]))
				req = build_req(CGETREQ, TSERIALNO, 0, NULL, response_pipe);
			else if (!strcmp("version", argv[2]))
				req = build_req(CGETREQ, TVERSION, 0, NULL, response_pipe);
			else if (!strcmp("rxpwr", argv[2]))
				req = build_req(CGETREQ, TRXPOWER, 0, NULL, response_pipe);
			else if (!strcmp("laser", argv[2]))
				req = build_req(CGETREQ, TLASER, 0, NULL, response_pipe);
		} else if (!strcmp("quit", argv[1])) {
			opt = 0;
			req = build_req(CTERMREQ, TTERMCAUSE, sizeof(opt), &opt, response_pipe);
		}
#ifndef _NDEBUG
		else if (!strcmp("verbose", argv[1])) {
			if (argc > 2) {
				verbose = !!strtol(argv[2], NULL, 0);
				fifo_reply(response_pipe, "Verbosity is %s\n", verbose ? "On" : "Off");
				return 0;
			} else
				status = EFEWARG;
		}
#endif
		else if (!strcmp("reset", argv[1])) {
			req = _req;
			abort_request(_req, "\n");
			if (req == NULL)
				fifo_reply(response_pipe, "\n");
			return 0;
		}
	} else
		status = EFEWARG;

	if (req == NULL)
		fifo_reply(response_pipe, "%s\n", strerror(errno));
	else if (req == (struct request *)0xdeadbeef) {
		switch (status) {
		case EUNIMPL:
			fifo_reply(response_pipe, "Unknow command\n");
			break;
		case EFEWARG:
			fifo_reply(response_pipe, "Need more arguments\n");
			break;
		}
	}
	return 0;
}

static void __attribute__ ((constructor)) ont_comm_module(void)
{
	strncpy(interface, nvram_match("OP_MODE", "0") ? "eth1" : "br0", sizeof(interface));
	fifo_cmd_register("ont", NULL, NULL, post_request);
}

int ont_channel(void)
{
	return _fd;
}

int ont_recv(void)
{
	return fsm_transit(EREAD, _req);
}
