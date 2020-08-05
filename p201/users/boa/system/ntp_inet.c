/*
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "sysconf.h"
#include "sys_utility.h"

#ifdef __DAVO__
#include <fcntl.h>
#include <dvflag.h>
#endif

#define NTPTMP_FILE "/tmp/ntp_tmp"
#define TZ_FILE "/etc/TZ"

static int isDaemon=0;

int daemon_already_running()
{
	#include <fcntl.h>
	#include <sys/stat.h>
	#include <errno.h>
	#define PID_FILE "/var/run/ntp_inet.pid"
		int pidFd;
		char pidBuf[16]={0};
		char *pid_file = PID_FILE;
		struct flock lock;

		pidFd=open(pid_file,O_RDWR|O_CREAT,S_IRUSR|S_IWUSR);
		if(pidFd<0)
		{
			fprintf(stderr, "could not create pid file: %s \n", pid_file);
			exit(1);
		}

		lock.l_type = F_WRLCK;
		lock.l_start = 0;
		lock.l_len = 0;
		lock.l_whence = SEEK_SET;
		if(fcntl(pidFd,F_SETLK,&lock)<0)
		{
			if(errno==EACCES || errno==EAGAIN)
			{
				close(pidFd);
				return 1;
			}
			fprintf(stderr, "can't lock %s:%s \n", pid_file,strerror(errno));
			exit(1);
		}

		ftruncate(pidFd,0);

		sprintf(pidBuf, "%ld\n", (long)getpid());
		write(pidFd,pidBuf,strlen(pidBuf)+1);
		return 0;
}

static void flag_update(int bit, int set)
{
	int fd;
	unsigned cmd[2] = {[0] = (set) ? bit : 0, [1] = bit };

	fd = open("/proc/dvflag", O_RDWR);
	if (fd >= 0) {
		write(fd, cmd, sizeof(cmd));
		close(fd);
	}
}

int main(int argc, char *argv[])
{
	int i;
	unsigned char ntp_server[64] = {0,}, ntp_server2[64] = {0,};
	unsigned short fail_wait_time = 30;
	unsigned int succ_wait_time = 86400;
	const int main_loop_time = 3600;
	const int retry_interval = 30;
	unsigned int cvt = 1;
	int retry_count = 0;
	char *svr;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
			case 'x':
				isDaemon = 1;
				break;
			default:
				fprintf(stderr, "%s: Unknown option\n", argv[i]);
				break;
			}
		}
	}

	if (argc > 2 && argv[2][0] != 0)
		snprintf(ntp_server, sizeof(ntp_server), "%s", argv[2]);

	if (argc > 5 && argv[5][0] != 0)
		snprintf(ntp_server2, sizeof(ntp_server2), "%s", argv[5]);
	else
		strcpy(ntp_server2, ntp_server);

	if (isDaemon == 1) {
		if (daemon(0, 1) == -1) {
			perror("ntp_inet fork error");
			return 0;
		}
	}

	if(daemon_already_running()) {
		fprintf(stderr, "ntp_inet daemon_already_running!\n");
		exit(1);
	}

	flag_update(DF_NTPSYNC, 0);

	for (;;) {
		int ret = 1;
		unsigned char cmdBuffer[100];
		FILE *fp_timeStatus = NULL;

		RunSystemCmd(NULL_FILE, "rm", "/tmp/ntp_tmp", NULL_STR);
		RunSystemCmd(NULL_FILE, "rm", "/tmp/timeStatus", NULL_STR);
		fp_timeStatus=fopen("/tmp/timeStatus","w+");

		if (retry_count > 2) {
			cvt = !cvt;
			retry_count = 0;
		}

		retry_count++;

		if (!cvt && retry_count >= 3)
			fail_wait_time = main_loop_time;
		else
			fail_wait_time = retry_interval;

		svr = (cvt) ? ntp_server : ntp_server2;
		sprintf((char *)cmdBuffer, "ntpclient -s -h %s -i 2 > %s", svr, NTPTMP_FILE);
		system((char *)cmdBuffer);

		if(isFileExist(NTPTMP_FILE))
		{
			FILE *fp = NULL;
			unsigned char ntptmp_str[100];
			memset(ntptmp_str,0x00,sizeof(ntptmp_str));

			fp = fopen(NTPTMP_FILE, "r");
			if (fp != NULL) {
				fgets((char *)ntptmp_str,sizeof(ntptmp_str),fp);
				fclose(fp);

				if (strlen((char *)ntptmp_str) != 0) {
					// success
					flag_update(DF_NTPSYNC, 1);
					fputs("2",fp_timeStatus);  //eTStatusSynchronized
					fclose(fp_timeStatus);
					RunSystemCmd(NULL_FILE, "echo", "ntp client success", NULL_STR);
					sleep(succ_wait_time);
					cvt = 1;
					retry_count = 0;
				} else {
					//RunSystemCmd(NULL_FILE, "echo", "ntp client fail", NULL_STR);
					fputs("1",fp_timeStatus); //eTStatusUnsynchronized
					fclose(fp_timeStatus);
					sleep(fail_wait_time - 2);
				}
			} else {
				fputs("3",fp_timeStatus); //eTStatusErrorFailed
				fclose(fp_timeStatus);
				RunSystemCmd(NULL_FILE, "echo", "Can't connect ntp server!!", NULL_STR);
				sleep(fail_wait_time - 2);
			}
		} else {
			fputs("3",fp_timeStatus);
			fclose(fp_timeStatus);
			sleep(fail_wait_time - 2);
		}
	}

	return 0;
}



