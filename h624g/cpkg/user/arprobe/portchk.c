#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <stdarg.h>
#include <sys/poll.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <assert.h>
#include <dvflag.h> 

#define DHCPC_BR0_PID		"/var/udhcpc/udhcpc-br0.pid"
#define DHCPC_ETH1_PID		"/var/udhcpc/udhcpc-eth1.pid"

#define LINK_UP 1
#define LINK_DOWN 0

static int event_pipe[2];
static int poll_timer = 0;
static struct timespec wan_link_down = {};
static struct timespec wan_link_up = {};

typedef struct {
	int changed;
	int last_changed_time[5];
} link_changed_t;

#define LINK_CHANGED_INFO "/var/last_change_link"

link_changed_t g_link;


static int monotonic_sec(struct timespec *ts)
{
	syscall(__NR_clock_gettime, CLOCK_MONOTONIC, ts);
	return (int)ts->tv_sec;
}

#if 1
static int get_poll_timer()
{
	// example
	int time = 3000;

	return time;
}
#endif

static long get_uptime(void)
{
	struct sysinfo info;
	sysinfo(&info);
	return info.uptime;
}

static void record_linkstate(unsigned int flag, unsigned int maskbit)
{
	int i;
	FILE *fp=NULL;
	unsigned long changed_time;

	changed_time = get_uptime()*100;

	switch (maskbit) {
		case DF_WANLINK:
			g_link.last_changed_time[0] = changed_time;
			g_link.changed |= 0x1;
			break;
		case DF_LANLINK1:
			g_link.last_changed_time[1] = changed_time;
			g_link.changed |= 0x2;
			break;
		case DF_LANLINK2:
			g_link.last_changed_time[2] = changed_time;
			g_link.changed |= 0x4;
		case DF_LANLINK3:
			g_link.last_changed_time[3] = changed_time;
			g_link.changed |= 0x8;
			break;
		case DF_LANLINK4:
			g_link.last_changed_time[4] = changed_time;
			g_link.changed |= 0x10;
			break;
		default:
			g_link.changed = 0;
			break;
	}
	if (g_link.changed) {
		if ((fp=fopen(LINK_CHANGED_INFO, "w"))) {
			if (fp) {
				//0: wan, 1: lan1,  2: lan2  3: lan3  1: lan4 
				fprintf(fp, "[ Last changed time(unit: tick): uptime * 100 ]\n");
				for ( i = 0; i < 5; i++ )
					fprintf(fp, "%u %s\n", g_link.last_changed_time[i], 
							((g_link.changed&(0x1<<i))? "update":"---"));
				fclose(fp);
			}
		}
	}
}

static long timespecdiff(struct timespec *starttime, struct timespec *finishtime)
{
	double delta;
	delta=(finishtime->tv_sec-starttime->tv_sec) * 1000000000LL;
	delta+=(finishtime->tv_nsec-starttime->tv_nsec);
	return (long)(delta/10000000LL);
}

static int fgetpid(const char *path)
{
	FILE *f;
	char buf[32];
	int pid = 0;

	if (!path || !path[0])
		return 0;

	f = fopen(path, "r");
	if (f) {
		buf[0] = '\0';
		fgets(buf, sizeof(buf), f);
		fclose(f);
		ydespaces(buf);
		if (buf[0])
			pid = strtol(buf, NULL, 10);
	}

	return (pid <= 0) ? 0 : pid;
}

static void kill_pidfile(char *f, int sig)
{
	int pid = fgetpid(f);
	if (pid > 0)
		kill(pid, sig);
}

static void probe_linkstate(unsigned int flag)
{
	int i, pn;
	static unsigned int flag_saved = 0;
	unsigned int mask_bit;
	long difftime;

	for (i=0; i<32; i++) {
		mask_bit = 1<<i;
		if ((flag_saved&mask_bit) != (flag&mask_bit)) {
			record_linkstate(flag, mask_bit);
			switch (mask_bit) {
				case DF_WANLINK:
					if (flag&mask_bit) {
						monotonic_sec(&wan_link_up);
						printf("Wan link connect\n");
						difftime = timespecdiff(&wan_link_down, &wan_link_up);
						if ((wan_link_down.tv_sec > 0) && (difftime > 150)) {
							usleep(200*1000);
							if (fgetpid("/var/sys_op") == 0) {
								kill_pidfile(DHCPC_ETH1_PID, SIGUSR1);
							} else {
								kill_pidfile(DHCPC_BR0_PID, SIGUSR1);
							}
						}
					} else {
						monotonic_sec(&wan_link_down);
						printf("Wan link disconnect\n");
					}
					break;
				case DF_LANLINK1:
				case DF_LANLINK2:
				case DF_LANLINK3:
				case DF_LANLINK4:
					pn = i;
					if (flag&mask_bit) {
						printf("Lan-%d link connect\n", pn);
					} else {
						printf("Lan-%d link disconnect\n", pn);
					}
					break;
			}
		}
	}
	flag_saved = flag;
}

int main(int argc, char *argv[])
{
	struct pollfd pfd[2];
	int flagfd, poll_count = 1;
	unsigned int flag;
	int waiths;

	memset(&wan_link_down, 0, sizeof(struct timespec));
	memset(&wan_link_up, 0, sizeof(struct timespec));

	if (pipe(event_pipe)==-1) {
		event_pipe[0] = -1;
		event_pipe[1] = -1;
	}

	flagfd = open("/proc/dvflag", O_RDWR);
	assert(flagfd > -1);

	flag = (DF_WANLINK | DF_LANLINK1 | DF_LANLINK2 | DF_LANLINK3 | DF_LANLINK4 | DF_WANBOUND);
//DVFLGIO_GETMASK_INDEX
	if (ioctl(flagfd, DVFLGIO_SETMASK, &flag))
		printf("ioctl error\n");

    pfd[0].fd = flagfd;
    pfd[0].events = POLLIN;
    pfd[0].revents = 0;

	if (event_pipe[0] > 0) {
		pfd[1].fd = event_pipe[0];
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;
		poll_count = 2;
	} else {
		pfd[1].revents = 0;
	}

	read(flagfd, (void *)&flag, sizeof(flag));
	if (!(flag & DF_WANLINK)) {
		monotonic_sec(&wan_link_down);
	}
	probe_linkstate(flag);
	while (1) {
		waiths = get_poll_timer();

		if (poll(&pfd, poll_count, waiths * 10) > 0) {
			if (pfd[0].revents) {
				if (read(flagfd, (void *)&flag, sizeof(flag)) > 0) {
					probe_linkstate(flag);
				} else {
					goto gotoexit;
				}
			} else {
			}
		}
	}

gotoexit:
	close(flagfd);

	if (event_pipe[0] > 0) {
		close(event_pipe[0]);
		close(event_pipe[1]);
	}

	return 0;
}
