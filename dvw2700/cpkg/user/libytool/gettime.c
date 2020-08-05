#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

time_t ygettime(struct timespec *ts)
{
	struct timespec ats;
	struct timespec *p = (ts) ? : &ats;

	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, p))
		return (time_t)-1;
	return p->tv_sec;
}
