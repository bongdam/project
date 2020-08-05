#ifndef __itimer_h_
#define __itimer_h_

#ifdef __cplusplus
extern "C" {
#endif

int itimer_cancel(long tid, int (*function)(unsigned long));
int itimer_creat(unsigned long data,
		 int (*function)(long, unsigned long),
		 struct timeval *timeout);
int itimer_modify(long tid, struct timeval *timeout);

#ifdef __cplusplus
}
#endif
#endif
