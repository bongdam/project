#ifndef __select_event_h_
#define __select_event_h_

#include <stdarg.h>
/* According to POSIX.1-2001 */
#include <sys/select.h>
/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include "linux_list.h"

#ifdef __GNUC__
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

#define NANE_MAXLEN	128
#define FD_WIDTH(a)	(a) + 1

#define FCTL_READ (1 << 0)
#define FCTL_WRITE (1 << 1)
#define FCTL_REGISTERD (1 << 2)
#define FCTL_EVENT_MASK (FCTL_READ | FCTL_WRITE)

struct select_event_base;
struct select_event_operation {
	int (*_fdset)(struct select_event_base *, fd_set *, fd_set *);
	int (*_read)(struct select_event_base *, int);
	int (*_write)(struct select_event_base *, int fd);
	int (*_accept)(struct select_event_base *, int fd);
	int (*_connect)(struct select_event_base *, int fd);
	int (*_close)(struct select_event_base *, int fd);
};

struct select_event_base {
	struct list_head list;
	long id;
	char name[NANE_MAXLEN];
	int fd;
	unsigned int flags;
	void *data;
	struct select_event_operation *ops;
	void *private;
};

#ifdef __cplusplus
extern "C" {
#endif
extern struct timeval event_iterate_jiffy;

int select_event_loop(void);
struct select_event_base * select_event_alloc(int,
	struct select_event_operation *, void *, const char *, ...);
int select_event_free(struct select_event_base *);
struct select_event_base *
select_event_iterate(int (*)(struct select_event_base *, void *), void *);
struct select_event_base *select_event_getbyid(long id);
struct select_event_base *select_event_getbyfd(int fd);

#ifdef __cplusplus
}
#endif

static inline int retrying(int errnr)
{
	return (errnr == EAGAIN
#if (EAGAIN != EWOULDBLOCK)
		|| errnr == EWOULDBLOCK
#endif
		|| errnr == EINTR);
}

#endif	/* __select_event_h_ */
