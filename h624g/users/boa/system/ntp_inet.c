/*
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dvflag.h>
#include "sysconf.h"
#include "sys_utility.h"
#include "libytool.h"

#define excvp(file, cmd, args...) ({ \
        char *___argv[] = { cmd, ## args, NULL }; \
        DoCmd(___argv, file); \
})

#define NTPTMP_FILE "/tmp/ntp_tmp"
#define TZ_FILE "/etc/TZ"
#define NTPSTATS "/tmp/ntp_ok"

static void ntp_sleep_timer(int fail_count, unsigned int wait_time)
{
	if (fail_count != 3 && fail_count != 6 && fail_count != 9)
		sleep(wait_time);
}

int main(int argc, char *argv[])
{
	int i, bg = 0;
	char ntp_server[60], ntp_server2[60], ntp_server3[60];
	unsigned short fail_wait_time = 300;
	unsigned int succ_wait_time = 3600;
	unsigned int invert = 0;
	int fail_count = 0;
	FILE *f;
	char buffer[100];
	char *args[12] = {NULL,};
	char *argp[] = { "ntpclient",
		"-s",
		"-h",
		NULL,
		"-i", "2",
		"-c", "1",
		"-g", "1000000",
		NULL
	};
	int fd;
	unsigned int flgs, cmd[2];
	struct sysinfo info;

	//printf("ntp_inet");
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

	if (argc > 6 && argv[6][0] != 0)
		snprintf(ntp_server3, sizeof(ntp_server3), "%s", argv[6]);
	else
		strcpy(ntp_server3, ntp_server);

	if (bg && daemon(0, 1) < 0) {
		perror(argv[0]);
		return 0;
	}

	fd = open("/proc/dvflag", O_RDWR);
	if (fd > -1) {
		fd_set rd;
		struct timeval tv = { .tv_sec = 120, .tv_usec = 0 };

		read(fd, &flgs, sizeof(flgs));
		if (!(flgs & DF_WANBOUND)) {
			flgs = DF_WANBOUND;
			ioctl(fd, DVFLGIO_SETMASK, &flgs);
			FD_ZERO(&rd);
			FD_SET(fd, &rd);
			select(fd + 1, &rd, NULL, NULL, &tv);
		}
		close(fd);
	} else
		flgs = 0;

	for (;;) {
		unlink(NTPTMP_FILE);
		// Keep TZ file written once otherwise the offset from UTC will be reset to 0.
		// Actually there happened a backward time stamp in syslog.
		// unlink("/var/TZ");
		if (fail_count > 8) {
			fail_count = 0;
			invert = 0;
			/* 2차 실패시 delay 없이 바로 1차 시도 */
//			sleep(succ_wait_time - fail_wait_time);
		} else if (fail_count == 3 || fail_count == 6) {
			if (invert == 0)
				invert = 1;
			else if (invert == 1)
				invert = 2;
			else
				invert = 0;
		}

		argp[3] = (!invert) ? ntp_server : (invert == 1) ? ntp_server2 : ntp_server3;
		DoCmd(argp, NTPTMP_FILE);
		if (isFileExist(NTPTMP_FILE)) {
			f = fopen(NTPTMP_FILE, "r");
			if (f != NULL) {
				buffer[0] = '\0';
				fgets(buffer, sizeof(buffer), f);
				fclose(f);
				if ((buffer[0] != '\0') &&
					(ystrargs(buffer, args, _countof(args), " \t\r\n", 0) >= 7) &&
					(strtol(args[0], NULL, 10) >= 25567)) {	/* 1970 - 1900 in seconds / 86400 */
					f = fopen(TZ_FILE, "w");
					if (f) {
						fprintf(f, "%s\n", (argc > 3) ? argv[3] : "");
						fclose(f);
					}

					if (argc > 4 && strcmp(argv[4], "1") == 0)
						excvp(NTPTMP_FILE, "date");

					if (!(flgs & DF_NTPSYNC)) {
						fd = open("/proc/dvflag", O_RDWR);
						if (fd > -1) {
							flgs = DF_NTPSYNC;
							cmd[0] = cmd[1] = DF_NTPSYNC;
							write(fd, cmd, sizeof(cmd));
							close(fd);
						}
						sysinfo(&info);
						syslog(LOG_INFO, "타임서버 %s로부터 현재 시간 설정 (uptime %ld)",
						       argp[3], info.uptime);
						yfecho(NTPSTATS, O_WRONLY|O_CREAT|O_TRUNC, 0644, "%s\n", argp[3]);
					}
					fail_count = 0;
					ntp_sleep_timer(fail_count, succ_wait_time);
					invert = 0;
				} else {
					yexecl(NULL, "sh -c \"snmp -m 10 %s &\"", argp[3]);
					fail_count += 1;
					ntp_sleep_timer(fail_count, fail_wait_time - 2);
				}
			} else {
				yexecl(NULL, "sh -c \"snmp -m 10 %s &\"", argp[3]);
				fail_count += 1;
				ntp_sleep_timer(fail_count, fail_wait_time);
			}
		} else {
			yexecl(NULL, "sh -c \"snmp -m 10 %s &\"", argp[3]);
			fail_count += 1;
			ntp_sleep_timer(fail_count, fail_wait_time);
		}
	}

	return 0;
}
