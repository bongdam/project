#ifndef __select_event_socket_h_
#define __select_event_socket_h_

#include "select_event.h"
#ifdef WIN32
#ifndef _NDEBUG
#include <crtdbg.h>
#endif
#include <stddef.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#else
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef AF_NETLINK
#include <linux/netlink.h>
#endif
#include <netdb.h>
#endif

union sockaddr_union {
	struct sockaddr s;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
#ifdef AF_NETLINK
	struct sockaddr_nl snl;
#endif
};

struct ip_addr {
	unsigned int af;	/* address family: AF_INET6 or AF_INET */
	unsigned short len;	/* address len, 16 or 4 */
	unsigned short port;	/* network byte order */
	union {			/* 64 bits aligned address */
		unsigned long addrl[16 / sizeof(long)];	/* long format */
		unsigned int addr32[4];
		unsigned short addr16[8];
		unsigned char addr[16];
	} u;

#define i_addr  u.addrl[0]

};

static inline int su2ip_addr(struct ip_addr *ip, union sockaddr_union *su)
{
	switch (su->s.sa_family) {
	case AF_INET:
		ip->af = AF_INET;
		ip->len = 4;
		ip->port = su->sin.sin_port;
		ip->i_addr = su->sin.sin_addr.s_addr;
		break;
	case AF_INET6:
		ip->af = AF_INET6;
		ip->len = 16;
		memcpy(ip->u.addr, &su->sin6.sin6_addr, 16);
		break;
	default:
		return -1;
	}
	return 0;
}

static inline int ip_addr2su(union sockaddr_union *su, struct ip_addr *ip)
{
	memset(su, 0, sizeof(union sockaddr_union));
	su->s.sa_family = ip->af;
	switch (ip->af) {
	case AF_INET6:
		memcpy(&su->sin6.sin6_addr, ip->u.addr, ip->len);
#ifdef HAVE_SOCKADDR_SA_LEN
		su->sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		su->sin6.sin6_port = ip->port;
		break;
	case AF_INET:
		memcpy(&su->sin.sin_addr, ip->u.addr, ip->len);
#ifdef HAVE_SOCKADDR_SA_LEN
		su->sin.sin_len = sizeof(struct sockaddr_in);
#endif
		su->sin.sin_port = ip->port;
		break;
	default:
		return -1;
	}
	return 0;
}

struct select_event_base;
struct select_event_operation;

#ifdef __cplusplus
extern "C" {
#endif

struct select_event_base * select_event_socket(int family, int type, int proto);
int select_event_bind(struct select_event_base *base, union sockaddr_union *addr);
int select_event_connect(struct select_event_base *base, union sockaddr_union *server,
			struct select_event_operation *ops, void *data);
int select_event_listen(struct select_event_base *base, union sockaddr_union *su,
			struct select_event_operation *ops, void *data, int backlog);
struct select_event_base * select_event_accept(struct select_event_base *base,
					struct select_event_operation *ops, void *data);
int select_event_attach(struct select_event_base *base,
			struct select_event_operation *ops, void *data);
int select_event_getpeername(struct select_event_base *base, union sockaddr_union *addr);
int select_event_getsockname(struct select_event_base *base, union sockaddr_union *addr);

#ifdef __cplusplus
}
#endif
#endif
