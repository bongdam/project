#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <search.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "itimer.h"
#include "select_event.h"

extern struct timeval *itimer_iterate(struct timeval *tvp);
extern void itimer_flush(void);
extern void getcurrenttime(struct timeval *tvp);

struct timeval event_iterate_jiffy;

static int fd_poll = -1;
static LIST_HEAD(header);
static void *root = NULL;
static long counter;

static int sub(const int a, const int b)
{
	return a - b;
}

/* generate unique id */
long genuid(void)
{
	unsigned short infinity_proof;

	for (infinity_proof = 1; infinity_proof; infinity_proof++) {
		if (++counter == 0L)
			counter = 1;
		if (!tfind((void *)counter, &root, (__compar_fn_t)sub)) {
			tsearch((void *)counter, &root, (__compar_fn_t)sub);
			break;
		}
	}

	return counter;
}

/* release unique id */
void putuid(long id)
{
	tdelete((void *)id, &root, (__compar_fn_t)sub);
}

#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

static int select_event_creat_poll(void)
{
	if (fd_poll >= 0)
		return 0;

	fd_poll = epoll_create(32);
	if (fd_poll < 0)
		return -1;

	fcntl(fd_poll, F_SETFD, fcntl(fd_poll, F_GETFD) | FD_CLOEXEC);
	return 0;
}

static void cntl_poll(struct select_event_base *base, unsigned int flags)
{
	if (!(flags & FCTL_EVENT_MASK)) {
		if (base->flags & FCTL_REGISTERD) {
			epoll_ctl(fd_poll, EPOLL_CTL_DEL, base->fd, 0);
			base->flags = flags & ~FCTL_REGISTERD;
		}
	} else {
		struct epoll_event ev = { .events = 0, .data = { .u64 = 0LL }};

		if (flags & FCTL_READ)
			ev.events |= EPOLLIN | EPOLLRDHUP;

		if (flags & FCTL_WRITE)
			ev.events |= EPOLLOUT;

		ev.data.ptr = base;

		epoll_ctl(fd_poll, (base->flags & FCTL_REGISTERD) ? \
				EPOLL_CTL_MOD : EPOLL_CTL_ADD, base->fd, &ev);
		base->flags = flags | FCTL_REGISTERD;
	}
}

static int select_event_fdset(fd_set *rset, fd_set *wset)
{
	struct select_event_base *base, *next;
	unsigned int flags;
	int maxevts = 0;

	list_for_each_entry_safe(base, next, &header, list) {
		if (base->ops->_fdset) {
			flags = base->flags & ~FCTL_EVENT_MASK;

			FD_CLR(base->fd, rset);
			FD_CLR(base->fd, wset);

			base->ops->_fdset(base, rset, wset);

			if (FD_ISSET(base->fd, rset))
				flags |= FCTL_READ;

			if (FD_ISSET(base->fd, wset))
				flags |= FCTL_WRITE;

			if (flags != base->flags)
				cntl_poll(base, flags);
		}
		maxevts++;
	}

	return maxevts;
}

static int select_event_fetch(size_t maxevts, int timeout)
{
	struct epoll_event events[maxevts];
	int n, nfds;
	struct select_event_base *base;

	nfds = epoll_wait(fd_poll, events, maxevts, timeout);

	getcurrenttime(&event_iterate_jiffy);

	for (n = 0; n < nfds; ++n) {
		base = events[n].data.ptr;
		if (!base || base->fd < 0)
			continue;

		if (events[n].events & EPOLLIN) {
			if (base->ops->_read) {
				switch (base->ops->_read(base, base->fd)) {
				case -1:
					if (retrying(errno))
						break;
				case 0:
					select_event_free(base);
					continue;
				default:
					break;
				}
			}
		}

		if (events[n].events & EPOLLOUT) {
			if (base->ops->_write && (base->ops->_write(base, base->fd) < 0)) {
				if (!retrying(errno)) {
					select_event_free(base);
					continue;
				}
			}
		}

		if (events[n].events & (EPOLLERR|EPOLLHUP)) {
			int nread;
			if (ioctl(base->fd, FIONREAD, &nread) || nread <= 0)
				select_event_free(base);
		}
	}

	return nfds;
}

struct select_event_base *select_event_alloc(int fd,
	struct select_event_operation *ops, void *data, const char *fmt, ...)
{
	struct select_event_base *base;
	va_list args;

	if (fd < 0 || ops == NULL)
		return NULL;
	base = (struct select_event_base *)calloc(sizeof(struct select_event_base), 1);
	if (base == NULL)
		return NULL;
	base->id = genuid();
	base->ops = ops;
	base->data = data;
	base->fd = fd;
	if (fmt)  {
		va_start(args, fmt);
		vsnprintf(base->name, sizeof(base->name), fmt, args);
		va_end(args);
	}

	list_add_tail(&base->list, &header);

	return base;
}

int select_event_free(struct select_event_base *base)
{
	if (base == NULL)
		return -1;

	epoll_ctl(fd_poll, EPOLL_CTL_DEL, base->fd, 0);
	list_del_init(&base->list);
	if (base->ops->_close)
		base->ops->_close(base, base->fd);
	if (base->fd > -1)
		close(base->fd);
	putuid(base->id);
	free(base);
	return 0;
}

static void select_event_flush(void)
{
	struct select_event_base *base;

	while (!list_empty(&header)) {
		base = list_entry(header.next, struct select_event_base, list);
		select_event_free(base);
	}
}

static void select_event_catcher(int signo)
{
	switch (signo) {
	case SIGINT:
		select_event_flush();
		close(fd_poll);
		exit(EXIT_SUCCESS);
		break;
	case SIGPIPE:
	default:
		break;
	}
}

static inline int timeval2msec(struct timeval *tv)
{
	return (tv) ? (int)((tv->tv_sec * 1000) + (tv->tv_usec / 1000)) : -1;
}

int select_event_loop(void)
{
	fd_set rdset, wrset;
	struct timeval tv, *tvp;

	if (select_event_creat_poll() < 0)
		exit(errno);

	signal(SIGINT, select_event_catcher);
	signal(SIGPIPE, select_event_catcher);

	for (;;) {
		tvp = itimer_iterate(&tv);
		if (select_event_fetch(select_event_fdset(&rdset, &wrset),
				timeval2msec(tvp)) < 0 && errno != EINTR) {
			fprintf(stderr, "%s escaping: %s\n", __func__, strerror(errno));
			break;
		}
	}

	select_event_flush();
	close(fd_poll);
	fd_poll = -1;
	return 0;
}

struct select_event_base *
select_event_iterate(int (*func)(struct select_event_base *, void *), void *data)
{
	struct select_event_base *base, *next;

	if (func) {
		list_for_each_entry_safe(base, next, &header, list)
			if (!func(base, data))
				return base;
	}
	return NULL;
}

static int compar(struct select_event_base *base, void *data)
{
	return (base->id == (int)data) ? 0 : -1;
}

struct select_event_base *select_event_getbyid(long id)
{
	return select_event_iterate(compar, (void *)id);
}

static int fdcompar(struct select_event_base *base, void *data)
{
	return (base->fd == (int)data) ? 0 : -1;
}

struct select_event_base *select_event_getbyfd(int fd)
{
	return select_event_iterate(fdcompar, (void *)fd);
}
