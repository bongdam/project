#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <dvflag.h>
#include <bcmnvram.h>
#include <libytool.h>

#include "reboot_schd.h"

static int nvram_atoi(char *name, int dfl)
{
        char *p = nvram_get(name);
        return (p) ? (int)strtol(p, NULL, 0) : dfl;
}

static void sigterm(int signo)
{
	unlink(REBOOT_SCHD_PID_FILE);
	exit(-1);
}

static void write_pid(char *file)
{
	int pid;
	FILE *fp = NULL;

	if (!file || !file[0])
		return;

	fp = fopen(file, "w");
	if (fp) {
		pid = getpid();
		fprintf(fp, "%d\n", pid);
		fclose(fp);
	}
}

static void check_ntp(void)
{
	int fd;
	int flag;

	while (1) {
		fd = open("/proc/dvflag", O_RDONLY);
		if (fd >= 0) {
			if (read(fd, (void *)&flag, sizeof(flag)) > 0) {
				if (flag & DF_NTPSYNC) {
					close(fd);
					break;
				}
			}
			close(fd);
		}
		sleep(1);
	}
}

static int get_week(int y, int m, int d)
{
	static int t[] = {0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4};

	y -= m < 3;

	return ((y + y/4 - y/100 + y/400 + t[m-1] + d) % 7);
}

static int next_polling(time_t reboot)
{
	time_t ctime;

	while (1) {
		ctime = time(NULL);
		if (reboot <= ctime) {
			break;
		}
		sleep(1);
	}

	return 1;
}

static int condition_reboot_calendar(reboot_schd *conf)
{
	time_t c_time, reboot_time;
	struct tm *now, *triger_time;
	int do_reboot = 0;
	int today_week, week[7] = {SUN, MON, TUE, WED, THU, FRI, SAT};
	int i = 0;

	time(&c_time);
	now = localtime(&c_time);
	today_week = get_week(now->tm_year + 1900, now->tm_mon + 1, now->tm_mday);

	for (i = 0; i <= 7; i++) {
		if (week[today_week] == conf->day) {
			now->tm_hour = conf->hour;
			now->tm_min = conf->min;
			now->tm_sec = 0;
			reboot_time = mktime(now) + (i * ONE_DAY);

			if (reboot_time < c_time) {
				today_week++;
				if (today_week >= 7)
					today_week = 0;
				continue;
			}
			break;
		} else {
			today_week++;
			if (today_week >= 7)
				today_week = 0;
		}
	}

	triger_time = (localtime(&reboot_time));

    syslog(LOG_INFO, "REBOOT SCHEDULE (%4d.%02d.%02d %02d:%02d:%02d)",
			triger_time->tm_year + 1900, triger_time->tm_mon + 1, triger_time->tm_mday,
			triger_time->tm_hour, triger_time->tm_min, triger_time->tm_sec);

	if (conf->debug) {
		DEBUG_PRINT("REBOOT SCHEDULE (%4d.%02d.%02d %02d:%02d:%02d)",
			triger_time->tm_year + 1900, triger_time->tm_mon + 1, triger_time->tm_mday,
			triger_time->tm_hour, triger_time->tm_min, triger_time->tm_sec);
	}

	do_reboot = next_polling(reboot_time);

	return do_reboot;
}

static void sys_reboot(reboot_schd *conf)
{
	syslog(LOG_INFO, "Reboot Scheduling do Reboot System");
	if (conf->debug)
		DEBUG_PRINT("Reboot Scheduling do Reboot System");
	yexecl(NULL, "reboot");
}

int main(int argc, char *argv[])
{
	int ntp = 0;
	struct timeval tv;
	int dv_enable = 0;
	reboot_schd dv_reboot;

	dv_enable = nvram_atoi("x_reboot_sched_enable", 0);
	if (dv_enable == 0) {
		DEBUG_PRINT("%s", "reboot_sched is disabled....");
		return 0;
	}

	signal(SIGTERM, sigterm);

	write_pid(REBOOT_SCHD_PID_FILE);

	memset(&dv_reboot, 0, sizeof(dv_reboot));

	dv_reboot.day = nvram_atoi("x_reboot_sched_week", 0);
	dv_reboot.hour = nvram_atoi("x_reboot_sched_hour", 0);
	dv_reboot.min = nvram_atoi("x_reboot_sched_min", 0);
	dv_reboot.debug = nvram_atoi("x_reboot_sched_debug", 0);

	check_ntp();

	while (1) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		select(0, NULL, NULL, NULL, &tv);

		if (condition_reboot_calendar(&dv_reboot))
			break;
	}

	sys_reboot(&dv_reboot);

	return 0;
}
