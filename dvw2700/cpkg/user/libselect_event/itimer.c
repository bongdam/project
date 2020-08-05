#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>

#ifdef THREAD_SAFE
#include <pthread.h>

static pthread_mutex_t itimerlist_lock = PTHREAD_MUTEX_INITIALIZER;
#define lock()		pthread_mutex_lock(&itimerlist_lock)
#define unlock()	pthread_mutex_unlock(&itimerlist_lock)
#else
#define lock()		do {} while (0);
#define unlock()	do {} while (0);
#endif

extern long genuid(void);
extern void putuid(long id);

#define timer_cmp(a, b, CMP)                                            \
  (((a)->tv_sec == (b)->tv_sec) ?                                       \
   (((signed)(a)->tv_usec - (signed)(b)->tv_usec) CMP 0) :              \
   (((signed)(a)->tv_sec - (signed)(b)->tv_sec) CMP 0))

struct itimer_list {
	struct itimer_list	*next;
	struct timeval		expires, timeout;
	unsigned long		data;
	int (*function)(long, unsigned long);
	long			id;
};

static struct itimer_list *itimerlist_head;
static const struct timeval poll_granul = { 1, 0 };	/* 1/sec */
static const struct timeval split_sec = { 0, 1 };

void getcurrenttime(struct timeval *tvp)
{
	struct timespec ts;
	syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &ts);
	tvp->tv_sec = ts.tv_sec;
	tvp->tv_usec = ts.tv_nsec / 1000;
}

static void __itimer_insert(struct itimer_list *itimer, long id)
{
	struct itimer_list **c;

	itimer->id = id;
	for (c = &itimerlist_head; c[0]; c = &c[0]->next) {
		if (timercmp(&itimer->expires, &c[0]->expires, <))
			break;
	}
	itimer->next = c[0];
	c[0] = itimer;
}

static void __itimer_delete(struct itimer_list *itimer)
{
	putuid(itimer->id);
	free(itimer);
}

int itimer_cancel(long tid, int (*function)(unsigned long))
{
	struct itimer_list **c;
	struct itimer_list *itimer = NULL;
	unsigned long data;

	if (tid == 0)
		return -1;

	lock();
	for (c = &itimerlist_head; c[0] != NULL; c = &c[0]->next) {
		if (c[0]->id == tid) {
			itimer = c[0];
			c[0] = itimer->next;
			data = itimer->data;
			__itimer_delete(itimer);
			break;
		}
	}
	unlock();

	if (itimer && function)
		function(data);

	return (itimer) ? 0 : -1;
}

int itimer_creat(unsigned long data,
		 int (*function)(long, unsigned long), struct timeval *timeout)
{
	struct itimer_list *itimer;
	struct timeval base;

	if (!function)
		return 0;

	itimer = (struct itimer_list *)malloc(sizeof(struct itimer_list));
	if (itimer == NULL)
		return 0;

	itimer->next = NULL;
	itimer->data = data;
	itimer->function = function;
	getcurrenttime(&base);
	timeradd(&base, timeout, &itimer->expires);
	itimer->timeout = *timeout;

	lock();

	__itimer_insert(itimer, genuid());

	unlock();

	return itimer->id;
}

int itimer_modify(long tid, struct timeval *timeout)
{
	struct itimer_list **c;
	struct itimer_list *itimer = NULL;
	struct timeval base;

	if (tid == 0)
		return -1;

	lock();
	for (c = &itimerlist_head; c[0] != NULL; c = &c[0]->next) {
		if (c[0]->id == tid) {
			itimer = c[0];
			c[0] = itimer->next;

			getcurrenttime(&base);
			timeradd(&base, timeout, &itimer->expires);
			itimer->timeout = *timeout;
			__itimer_insert(itimer, itimer->id);
			break;
		}
	}
	unlock();
	return (itimer != NULL);
}

struct timeval *itimer_iterate(struct timeval *tvp)
{
	struct timeval tv;
	struct itimer_list *c;
	int res;

	*tvp = poll_granul;

	lock();
	if (itimerlist_head != NULL) {
		getcurrenttime(&tv);
		do {
			if (timer_cmp(&itimerlist_head->expires, &tv, <=)) {
				c = itimerlist_head;
				itimerlist_head = c->next;
				/*
				 * At this point, the schedule queue is still intact.  We
				 * have removed the first event and the rest is still there,
				 * so it's permissible for the function to add new events, but
				 * trying to delete itself won't work because it isn't in
				 * the schedule queue.  If that's what it wants to do, it
				 * should return 0.
				 */
				unlock();

				res = c->function(c->id, c->data);

				lock();
				if (res) {
					timeradd(&tv, &c->timeout, &c->expires);
					__itimer_insert(c, c->id);
				} else
					__itimer_delete(c);
			} else
				break;
		} while (itimerlist_head != NULL);

		if (itimerlist_head != NULL) {
			timersub(&itimerlist_head->expires, &tv, tvp);
			if (timer_cmp(tvp, &poll_granul, >))
				*tvp = poll_granul;
			else if (timer_cmp(tvp, &split_sec, <=))
				*tvp = split_sec;
		}
	}
	unlock();

	return tvp;
}

void __attribute__ ((destructor)) itimer_flush(void)
{
	struct itimer_list *c;

	lock();
	while (itimerlist_head != NULL) {
		c = itimerlist_head;
		itimerlist_head = c->next;
		__itimer_delete(c);
	}
	unlock();
}
