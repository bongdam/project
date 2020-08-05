#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>

static int fecho(const char *path, const char *fmt, ...)
{
	va_list ap;
	FILE *f;
	int n;

	f = fopen(path, "w+");
	if (f) {
		va_start(ap, fmt);
		n = vfprintf(f, fmt, ap);
		va_end(ap);
		fclose(f);
	} else
		n = 0;
	return n;
}

static void die(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

static void watchdog_write_pidfile(void)
{
	char pidfile[80];
	char pidbuf[16];
	int fd;
	int ret;

	snprintf(pidfile, sizeof(pidfile), "/var/run/%s.pid", "watchdog");
	fd = open(pidfile, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			die("%s: opening pidfile %s for read: %s\n", __func__,
			    pidfile, strerror(errno));
		/* ENOENT is good: the pidfile doesn't exist */
	} else {
		/* the pidfile exists: read it and check whether the named pid
		   is still around */
		int pid;
		char *end;

		ret = read(fd, pidbuf, sizeof(pidbuf));
		if (ret < 0)
			die("%s: read of pre-existing %s failed: %s\n",
			    __func__, pidfile, strerror(errno));
		pid = strtol(pidbuf, &end, 10);
		if (*end != '\0' && *end != '\n')
			die("%s: couldn't parse \"%s\" as a pid (from file %s); aborting\n",
			    __func__, pidbuf, pidfile);
		ret = kill(pid, 0);	/* try sending signal 0 to the pid to check it exists */
		if (ret == 0)
			die("%s: %s contains pid %d which is still running; aborting\n",
			    __func__, pidfile, pid);
		/* pid doesn't exist, looks like we can proceed */
		close(fd);
	}

	if (fecho(pidfile, "%d\n", getpid()) <= 0)
		die("%s: %m\n", pidfile);
}

static void watchdog_func(int signo)
{
	fecho("/proc/watchdog_kick", "111");
}

int main(int argc, char **argv)
{
	pid_t pid;
	char tmpBuff[30] = { 0 };
	int fd;
	int interval;
	int sec, micro_sec;
	sigset_t sigset;

	if (argc >= 2)
		interval = atoi(argv[1]);
	else
		interval = 500;

	if (interval >= 10000) {
		printf("watchdog interval too long,should not more than 10s\n");
		interval = 1000;
	}

	sec = interval / 1000;
	micro_sec = (interval % 1000) * 1000;

	watchdog_write_pidfile();

	/* unblock sigalarm and sigterm signal */
	sigaddset(&sigset, SIGALRM);
	if (sigprocmask(SIG_UNBLOCK, &sigset, NULL) < 0)
		printf("sigprocmask error\n");

	// Register watchdog_func to SIGALRM
	signal(SIGALRM, watchdog_func);

	struct itimerval tick;
	memset(&tick, 0, sizeof(tick));
	//printf("interval:%d.\n",interval);

	// Timeout to run function first time
	tick.it_value.tv_sec = sec;	// sec
	tick.it_value.tv_usec = micro_sec;	// micro sec.

	// Interval time to run function
	tick.it_interval.tv_sec = sec;
	tick.it_interval.tv_usec = micro_sec;

	pid = getpid();
	snprintf(tmpBuff, sizeof(tmpBuff), "renice -19 %d", pid);
	system(tmpBuff);
	//stop watchdog first
	fecho("/proc/watchdog_kick", "1\n");
	fecho("/proc/watchdog_cmd", "enable 0 interval 0\n");

	// resume watchdog
#ifdef CONFIG_RTL_8197F
	fecho("/proc/watchdog_cmd", "enable 1 interval 32\n");
#else
	fecho("/proc/watchdog_cmd", "enable 1 interval 10\n");
#endif
	fecho("/proc/watchdog_kick", "1\n");

	if (setitimer(ITIMER_REAL, &tick, NULL))
		die("%s: %m\n", argv[0]);

	while (1)
		pause();
	return 0;
}
