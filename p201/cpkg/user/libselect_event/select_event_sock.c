#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "select_event_sock.h"

enum tcp_conn_states {
	S_CONN_ERROR = -2,
	S_CONN_EOF = -1,
	S_CONN_INIT = 0,
	S_CONN_LISTEN,
	S_CONN_ACCEPT,
	S_CONN_NBLOCK_CONNECT,
	S_CONN_CONNECT
};

struct sock;
struct sock_proto_operation {
	const char name[16];
	int (*so_read)(struct select_event_base *, struct sock *);
	int (*so_write)(struct select_event_base *, struct sock *);
};

struct sock {
	struct sock_proto_operation *p_ops;
	struct select_event_operation *ops;
	int state;
	struct ip_addr peer, local;
};

static int so_naming(struct select_event_base *base, struct sock *sk)
{
	char buf[INET6_ADDRSTRLEN], any[sizeof(struct in6_addr)] = { 0 };
	int n;

	if (!inet_ntop(sk->local.af, &sk->local.i_addr, buf, sizeof(buf)))
		return -1;
	n = snprintf(base->name, sizeof(base->name), "%s://%s:%u",
		     sk->p_ops->name, buf, ntohs(sk->local.port));
	if (sizeof(base->name) <= n)
		return (int)(sizeof(base->name) - 1);

	if (sk->state != S_CONN_LISTEN) {
		if (!inet_ntop(sk->peer.af, &sk->peer.i_addr, buf, sizeof(buf)))
			return -1;
		snprintf(&base->name[n], sizeof(base->name) - n, "/%s:%u",
			 buf, ntohs(sk->peer.port));
	} else {
		if (!inet_ntop(sk->local.af, any, buf, sizeof(buf)))
			return -1;
		snprintf(&base->name[n], sizeof(base->name) - n, "/%s:*", buf);
	}

	return (int)strlen(base->name);
}

static void so_naming_on_connect(struct select_event_base *base, struct sock *sk)
{
	union sockaddr_union su;
	socklen_t len = sizeof(union sockaddr_union);

	if (getsockname(base->fd, &su.s, &len) == 0) {
		su2ip_addr(&sk->local, &su);
		so_naming(base, sk);
	}
}

static int so_tcpread(struct select_event_base *base, struct sock *sk)
{
	int bytes = -1;

	switch (sk->state) {
	case S_CONN_ACCEPT:
	case S_CONN_CONNECT:
		if (sk->ops->_read == NULL)
			errno = ENOSYS;
		else if ((bytes = sk->ops->_read(base, base->fd)) == 0)
			sk->state = S_CONN_EOF;
		return bytes;

	case S_CONN_LISTEN:
		/* TCP Listener Never returns error */
		if (sk->ops->_accept == NULL)
			errno = ENOSYS;
		else if (sk->ops->_accept(base, base->fd) == 0)
			return 1;	/* assuming 1 octet read */
		break;
	}
	return -1;
}

static int so_tcpwrite(struct select_event_base *base, struct sock *sk)
{
	int n, errnr, bytes = -1;

	switch (sk->state) {
	case S_CONN_ACCEPT:
	case S_CONN_CONNECT:
		if (sk->ops->_write == NULL)
			errno = ENOSYS;
		else if ((bytes = sk->ops->_write(base, base->fd)) < 0) {
			if (!retrying(errno))
				sk->state = S_CONN_ERROR;
		}
		return bytes;

	case S_CONN_NBLOCK_CONNECT:
		n = sizeof(errnr);	/* must consume error pended */
		getsockopt(base->fd, SOL_SOCKET, SO_ERROR, (void *)&errnr, (socklen_t *)&n);
		switch (errnr) {
		case 0:
			sk->state = S_CONN_CONNECT;
			if (!base->name[0])
				so_naming_on_connect(base, sk);
			if (sk->ops->_connect)
				sk->ops->_connect(base, base->fd);
			break;
		case EINPROGRESS:
		case EALREADY:
		default:
			/* do we need? */
			errno = errnr;
			sk->state = S_CONN_ERROR;
			return -1;
		}
		break;
	}

	return 0;
}

/* read operation for UDP protocol */
static int so_udpread(struct select_event_base *base, struct sock *sk)
{
	return (sk->ops->_read) ? sk->ops->_read(base, base->fd) : ({ errno = ENOSYS; -1; });
}

static int so_udpwrite(struct select_event_base *base, struct sock *sk)
{
	int bytes = -1;
	if (sk->ops->_write == NULL)
		errno = ENOSYS;
	else if ((bytes = sk->ops->_write(base, base->fd)) == 0)
		sk->state = S_CONN_EOF;
	return bytes;
}

static int so_receive(struct select_event_base *base, int fd)
{
	struct sock *sk = (struct sock *)base->private;
	return sk->p_ops->so_read(base, sk);
}

static int so_write(struct select_event_base *base, int fd)
{
	struct sock *sk = (struct sock *)base->private;
	return sk->p_ops->so_write(base, sk);
}

#ifdef WIN32
static int so_fdset(struct select_event_base *base, fd_set *rdset, fd_set *wrset, fd_set *eset)
#else
static int so_fdset(struct select_event_base *base, fd_set *rdset, fd_set *wrset)
#endif
{
	int fd;
	struct sock *sk = (struct sock *)base->private;

	fd = base->fd;
	switch (sk->state) {
	case S_CONN_LISTEN:
		FD_SET(fd, rdset);
		break;
	case S_CONN_ACCEPT:
	case S_CONN_CONNECT:
		if (sk->ops->_fdset)
			sk->ops->_fdset(base, rdset, wrset
#ifdef WIN32
					, eset
#endif
					);
		break;
	case S_CONN_NBLOCK_CONNECT:
		FD_SET(fd, wrset);
#ifdef WIN32
		FD_SET(fd, eset);
#endif
		break;
	case S_CONN_INIT:
		return -1;
	default:
		break;
	}

	return (FD_ISSET(fd, rdset) || FD_ISSET(fd, wrset)
#ifdef WIN32
		|| FD_ISSET(fd, eset)
#endif
		) ? fd : -1;
}

static int so_close(struct select_event_base *base, int fd)
{
	struct sock *sk = (struct sock *)base->private;
	int status = 0;

	if (sk == NULL)
		return -1;
	if (sk->ops->_close)
		status = sk->ops->_close(base, base->fd);
	free(sk);
	return status;
}

static struct sock_proto_operation udp_ops __attribute__ ((__used__)) = {
	.name = "udp",
	.so_read = so_udpread,
	.so_write = so_udpwrite
};

static struct sock_proto_operation tcp_ops __attribute__ ((__used__)) = {
	.name = "tcp",
	.so_read = so_tcpread,
	.so_write = so_tcpwrite
};

static struct select_event_operation nulop __attribute__ ((__used__));

static struct select_event_operation sockop __attribute__ ((__used__)) = {
	._fdset = so_fdset,
	._read = so_receive,
	._write = so_write,
	._close = so_close,
};

int so_nonblocking(int s, int nb)
{
#ifdef WIN32
	return ioctlsocket(s, FIONBIO, (u_long *)&nb);
#else
	if (nb)
		return fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
	else
		return fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK);
#endif
}

struct select_event_base * select_event_socket(int family, int type, int proto)
{
	struct select_event_base *base;
	struct sock *sk;
	struct sock_proto_operation *p_ops = NULL;
	int fd;

	switch (type) {
	case SOCK_STREAM:
		p_ops = &tcp_ops;
		break;
	case SOCK_DGRAM:
	case SOCK_RAW:
		p_ops = &udp_ops;
		break;
	default:
		errno = EINVAL;
		return NULL;
	}

	fd = socket(family, type, proto);
	if (fd < 0)
		return NULL;

	so_nonblocking(fd, 1);

	sk = (struct sock *)calloc(sizeof(struct sock), 1);
	if (sk == 0) {
		close(fd);
		return NULL;
	}

	sk->state = S_CONN_INIT;
	sk->p_ops = p_ops;
	sk->ops = &nulop;
	base = select_event_alloc(fd, &sockop, NULL, NULL);
	if (base == NULL) {
		close(fd);
		free(sk);
	} else
		base->private = sk;

	return base;
}

int select_event_bind(struct select_event_base *base, union sockaddr_union *addr)
{
	struct sock *sk;

	if (base == NULL || base->private == NULL)
		return -1;
	if (base->fd < 0)
		return -1;
	if (addr == NULL)
		return -1;
	sk = (struct sock *)base->private;
	if (bind(base->fd, &addr->s, sizeof(addr->s)))
		return -1;

	if (addr->sin.sin_port == 0) {
		socklen_t n = sizeof(addr->s);
		if (getsockname(base->fd, &addr->s, &n))
			return -1;
	}
	return su2ip_addr(&sk->local, addr);
}

int select_event_connect(struct select_event_base *base, union sockaddr_union *server,
			struct select_event_operation *ops, void *data)
{
	struct sock *sk;

	if (base == NULL || base->private == NULL)
		return -1;
	if (base->fd < 0)
		return -1;
	if (ops == NULL || server == NULL)
		return -1;
	sk = (struct sock *)base->private;
retry:
	if (connect(base->fd, &server->s, sizeof(server->sin)) < 0) {
		switch (errno) {
		case EINTR:
			goto retry;
		case EINPROGRESS:
		case EALREADY:
			sk->state = S_CONN_NBLOCK_CONNECT;
			break;
		default:
			return -1;
		}
	} else
		sk->state = S_CONN_CONNECT;
	base->data = data;
	sk->ops = ops;
	if (su2ip_addr(&sk->peer, server))
		snprintf(base->name, sizeof(base->name), "%s://%d/%u/%02X%02X%02X%02X\n",
			 sk->p_ops->name, server->s.sa_family,
			 (u_int16_t)(server->s.sa_data[0] << 8 | server->s.sa_data[1]),
			 server->s.sa_data[2], server->s.sa_data[3],
			 server->s.sa_data[4], server->s.sa_data[5]);
	else if (sk->state == S_CONN_CONNECT)
		so_naming_on_connect(base, sk);

	if (sk->state == S_CONN_CONNECT && sk->ops->_connect)
		sk->ops->_connect(base, base->fd);
	return 0;
}

static inline unsigned int ptonl(unsigned char *p)
{
	return ((((unsigned int)p[0] & 0xff) << 24) |
		(((unsigned int)p[1] & 0xff) << 16) |
		(((unsigned int)p[2] & 0xff) <<  8) |
		(((unsigned int)p[3] & 0xff)      ));
}

int select_event_listen(struct select_event_base *base, union sockaddr_union *su,
			struct select_event_operation *ops, void *data, int backlog)
{
	struct sock *sk;
	int n;

	if (base == NULL || base->private == NULL)
		return -1;
	if (base->fd < 0)
		return -1;
	if (ops == NULL || su == NULL)
		return -1;
	sk = (struct sock *)base->private;

	(void)fcntl(base->fd, F_SETFD, FD_CLOEXEC);
#if !defined(TCP_DONT_REUSEADDR)
	{
	/* Stevens, "Network Programming", Section 7.5, "Generic Socket Options":
	 * "...server started,..a child continues..on existing connection..
	 * listening server is restarted...call to bind fails ... ALL TCP servers
	 * should specify the SO_REUSEADDRE option to allow the server to be restarted
	 * in this situation. Indeed, without this option, the server can't restart. -jiri
	 */
	int opt = 1;
	if (setsockopt(base->fd, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt)))
		return -1;
	}
#endif
	if (bind(base->fd, &su->s, sizeof(su->s)) || listen(base->fd, backlog))
		return -1;
	if (su->sin.sin_port == 0) {
		n = sizeof(su->s);
		if (getsockname(base->fd, &su->s, (socklen_t *)&n))
			return -1;
	}

	base->data = data;
	sk->ops = ops;
	sk->state = S_CONN_LISTEN;
	if (!su2ip_addr(&sk->local, su))
		so_naming(base, sk);
	else
		snprintf(base->name, sizeof(base->name), "%s://%d/%u/%08X\n",
			 sk->p_ops->name, su->s.sa_family,
			 (u_int16_t)(su->s.sa_data[0] << 8 | su->s.sa_data[1]),
			 ptonl((u_int8_t *)&su->s.sa_data[2]));

	return 0;
}

struct select_event_base * select_event_accept(struct select_event_base *base,
					struct select_event_operation *ops, void *data)
{
	struct sock *sk, *master;
	struct select_event_base *offspring;
	union sockaddr_union su;
	int fd, len;

	if (base == NULL || (master = (struct sock *)base->private) == NULL)
		return NULL;
	if (base->fd < 0)
		return NULL;
	if (ops == NULL)
		return NULL;

	len = sizeof(su);
	fd = accept(base->fd, &su.s, (socklen_t *)&len);
	if (fd < 0)
		return NULL;
	so_nonblocking(fd, 1);

	sk = (struct sock *)calloc(sizeof(struct sock), 1);
	if (sk == 0) {
		close(fd);
		return NULL;
	}

	sk->state = S_CONN_ACCEPT;
	sk->p_ops = master->p_ops;
	sk->ops = ops;
	su2ip_addr(&sk->peer, &su);
	if (getsockname(fd, &su.s, (socklen_t *)&len) == 0)
		su2ip_addr(&sk->local, &su);
	else
		sk->local = master->local;
	offspring = select_event_alloc(fd, &sockop, NULL, NULL);
	if (offspring == NULL) {
		close(fd);
		free(sk);
		return NULL;
	} else {
		offspring->data = data;
		offspring->private = sk;
		so_naming(offspring, sk);
	}

	return offspring;
}

int select_event_attach(struct select_event_base *base,
			struct select_event_operation *ops, void *data)
{
	struct sock *sk;

	if (base == NULL || base->private == NULL)
		return -1;
	if (base->fd < 0)
		return -1;
	if (ops == NULL)
		return -1;
	sk = (struct sock *)base->private;
	base->data = data;
	sk->ops = ops;
	if (sk->state != S_CONN_ACCEPT)
		sk->state = S_CONN_CONNECT;

	return 0;
}

int select_event_getpeername(struct select_event_base *base, union sockaddr_union *addr)
{
	struct sock *sk = (struct sock *)base->private;
	return (sk) ? ip_addr2su(addr, &sk->peer) : -1;
}

int select_event_getsockname(struct select_event_base *base, union sockaddr_union *addr)
{
	struct sock *sk = (struct sock *)base->private;
	return (sk && sk->local.af) ? ip_addr2su(addr, &sk->local) : -1;
}
