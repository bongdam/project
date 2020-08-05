
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include "timeout.h"

//#define MAINDEBUG(x)	printf(x)


static struct callout *callout = NULL;	/* Callout list */
#ifndef __DAVO__
static struct timeval timenow;	/* Current time */
#endif

#ifdef __DAVO__
static void get_mono(struct timespec *ts);
static int getmonotime(struct timeval *tvp);
#endif

/*
 * timeout - Schedule a timeout.
 *
 * Note that this timeout takes the number of seconds, NOT hz (as in
 * the kernel).
 */
void
timeout(func, arg, time, handle)
    void (*func) __P((void *));
    void *arg;
    int time;
    struct callout *handle;
{
#if defined(__DAVO__)
	struct callout *p = callout;
	struct timeval tv;

	while (p && (p != handle))
		p = p->c_next;

	handle->c_arg = arg;
	handle->c_func = func;
	getmonotime(&tv);
	handle->c_time.tv_sec = tv.tv_sec + time;
	handle->c_time.tv_usec = tv.tv_usec;

	if (p == NULL) {
		handle->c_next = callout;
		callout = handle;
	}
#else	
    struct callout *p = callout;

    //MAINDEBUG(("Timeout %p:%p in %d seconds.", func, arg, time));
  
    handle->c_arg = arg;
    handle->c_func = func;
    gettimeofday(&timenow, NULL);
    handle->c_time.tv_sec = timenow.tv_sec + time;
    handle->c_time.tv_usec = timenow.tv_usec;

	/* try to find out the handle */
    while (p) {
	    if(p == handle) {
			return;
		}
		p = p->c_next;
    }
  
	/* put handle in the front */
    handle->c_next = callout;
    callout = handle;
#endif    
}


/*
 * untimeout - Unschedule a timeout.
 */
void
untimeout(handle)
struct callout *handle;
{
	struct callout **q, *p;
  
    //MAINDEBUG(("Untimeout %p:%p.", func, arg));
  
	/* Remove the entry matching timeout and remove it from the list. */
	for (q = &callout; (p = *q); q = &p->c_next)
		if (p == handle) {
			*q = p->c_next;
			break;
		}

}


/*
 * calltimeout - Call any timeout routines which are now due.
 */

#if defined(__DAVO__)
#define timer_cmp(a, b, CMP)                                                  \
  (((a)->tv_sec == (b)->tv_sec) ?                                             \
   ((a)->tv_usec CMP (b)->tv_usec) :                                          \
   ((signed long)((a)->tv_sec - (b)->tv_sec) CMP 0))

void calltimeout(struct timeval *timeout)
{
	struct callout *p, *q;
	struct timeval tv, delta;

	timeout->tv_sec = 1;
	timeout->tv_usec = 0;

	getmonotime(&tv);
	for (p = callout; p; p = q) {
		q = p->c_next;
		timersub(&p->c_time, &tv, &delta);
		if (((signed long)delta.tv_sec < 0) || (!delta.tv_sec && !delta.tv_usec))
			p->c_func(p->c_arg);
		else if (timer_cmp(timeout, &delta, >))
			*timeout = delta;
	}

	if (timeout->tv_sec == 0 && timeout->tv_usec < 1000)
		timeout->tv_usec = 1000;
}

int timepending(struct callout *handle)
{
	struct callout *p;

	for (p = callout; p; p = p->c_next) {
		if (p == handle)
			return 1;
	}
	return 0;
}
#else //__DAVO__

void
calltimeout()
{
    struct callout *p = callout;
	struct callout *q;
	
	if (gettimeofday(&timenow, NULL) < 0)
	    //fatal("Failed to get time of day: %m");
    	printf("Failed to get time of day: %m");

    while (p) {
	    if((timenow.tv_sec > p->c_time.tv_sec) || \
	    	(timenow.tv_sec == p->c_time.tv_sec && timenow.tv_usec >= p->c_time.tv_usec)) {
			(*p->c_func)(p->c_arg);
		}
		p = p->c_next;
    }
}
#endif

#if !defined(__DAVO__)
/*
 * timeleft - return the length of time until the next timeout is due.
 */
static struct timeval *
timeleft(tvp)
    struct timeval *tvp;
{
    if (callout == NULL)
	return NULL;

    gettimeofday(&timenow, NULL);
    tvp->tv_sec = callout->c_time.tv_sec - timenow.tv_sec;
    tvp->tv_usec = callout->c_time.tv_usec - timenow.tv_usec;
    if (tvp->tv_usec < 0) {
	tvp->tv_usec += 1000000;
	tvp->tv_sec -= 1;
    }
    if (tvp->tv_sec < 0)
	tvp->tv_sec = tvp->tv_usec = 0;

    return tvp;
}

void test_timeout(void *arg)
{
	printf("test timeout!!\n");
	timeout(&test_timeout, 0, 3);
}

void main(void)
{
struct	callout test_handle;
	timeout(&test_timeout, 0, 3, &test_handle);
	while(1)
		calltimeout();
}

#endif

#ifdef __DAVO__
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
static void get_mono(struct timespec *ts)
{
	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, ts))
		perror("clock_gettime(MONOTONIC) failed");
}

static int getmonotime(struct timeval *tvp)
{
	struct timespec ts;
	get_mono(&ts);
	if (tvp) {
		tvp->tv_sec = ts.tv_sec;
		tvp->tv_usec = ts.tv_nsec / 1000;
	}
	return 0;
}
#endif
