/*
 */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <dvflag.h>
#include <libytool.h>

#define NTPTMP_FILE "/tmp/ntp_tmp"
#define TZ_FILE "/etc/TZ"
#define NTPSTATS "/tmp/ntp_ok"

static u_int32_t watiflag(u_int32_t bit, int timeout)
{
	struct pollfd pfd;
	u_int32_t flg = 0;

	pfd.fd = open("/proc/dvflag", O_RDWR);
	if (pfd.fd > -1) {
		read(pfd.fd, &flg, sizeof(flg));
		if (bit && !(flg & bit)) {
			ioctl(pfd.fd, DVFLGIO_SETMASK, &bit);
			pfd.events = POLLIN;
			pfd.revents = 0;
			poll(&pfd, 1, timeout);
		}
		close(pfd.fd);
	}
	return flg;
}

static void flag_update(int bit, int set)
{
	int fd = open("/proc/dvflag", O_RDWR);
	if (fd > -1) {
		u_int32_t cmd[2] = { [0] = (set) ? bit : 0, [1] = bit };
		write(fd, cmd, sizeof(cmd));
		close(fd);
	}
}

static void ntp_sleep_timer(unsigned int wait_time)
{
	do {
		wait_time = sleep(wait_time);
	} while (wait_time);
}

int main(int argc, char *argv[])
{
	int i, bg = 0;
	char ntp_server[40], ntp_server2[40];
	unsigned int fail_wait_time = 30;
	const unsigned int succ_wait_time = 86400;
	const int main_loop_time = 3600;
	const int retry_interval = 30;
	unsigned int cvt = 1;
	int retry_count = 0;
	char buffer[100], *srv;
	unsigned int flgs;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
			case 'x':
				bg = 1;
				break;
			default:
				//fprintf(stderr, "%s: Unknown option\n", argv[i]);
				break;
			}
		}
	}

	ntp_server[0] = '\0';
	if (argc > 2 && argv[2][0] != 0)
		snprintf(ntp_server, sizeof(ntp_server), "%s", argv[2]);

	if (argc > 5 && argv[5][0] != 0)
		snprintf(ntp_server2, sizeof(ntp_server2), "%s", argv[5]);
	else
		strcpy(ntp_server2, ntp_server);

	if (bg && daemon(0, 1) < 0) {
		perror(argv[0]);
		return 0;
	}

	flgs = watiflag(DF_WANLINK, 5 * 1000);
	flgs = watiflag(DF_WANBOUND, 120 * 1000);
	for (;;) {
		unlink(NTPTMP_FILE);

		if (retry_count > 2) {
			cvt = !cvt;
			retry_count = 0;
		}

		retry_count++;

		if (!cvt && retry_count >= 3)
			fail_wait_time = main_loop_time;
		else
			fail_wait_time = retry_interval;

		srv = (cvt) ? ntp_server : ntp_server2;
		yexecl(">" NTPTMP_FILE, "ntpclient -s -h %s -i 2 -c 1 -g 1000000", srv);
		buffer[0] = '\0';
		if (yfcat(NTPTMP_FILE, "%99s", buffer) > 0 && buffer[0]) {
			if (!strstr(buffer, srv)) {
				yecho(TZ_FILE, "%s\n", argv[3]);
				if (argc > 4 && strcmp(argv[4], "1") == 0)
					yexecl(">" NTPTMP_FILE, "date");

				if (!(flgs & DF_NTPSYNC)) {
					flag_update(DF_NTPSYNC, 1);
					syslog(LOG_INFO, "타임서버 %s로부터 현재 시간 설정 (uptime %ld)",
					       srv, ygettime(NULL));
					yecho(NTPSTATS, "%s\n", srv);
				}
				ntp_sleep_timer(succ_wait_time);
				cvt = 1;
				retry_count = 0;
			} else {
				syslog(LOG_INFO, "타임서버 %s로부터 현재 시간 설정 실패", srv);
				ntp_sleep_timer(fail_wait_time - 2);
			}
		} else {
			syslog(LOG_INFO, "타임서버 %s로부터 현재 시간 설정 실패", srv);
			ntp_sleep_timer(fail_wait_time - 2);
		}
	}

	return 0;
}
