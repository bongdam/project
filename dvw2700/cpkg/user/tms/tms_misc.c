#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <libytool.h>
#include <furl.h>
#include "tms_misc.h"

#define read_pid(file) read_int(file,0)

unsigned int confirm_server_ip(char *ip_info, char *ip_n, int ip_n_len)
{
	struct addrinfo hints, *res = NULL;
	struct sockaddr_in *ipv4 = NULL;
	int status;
	unsigned int addr_r = 0;

	memset(ip_n, 0, ip_n_len);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	if ((status = getaddrinfo(ip_info, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return 0;
	}
	if (res->ai_family == AF_INET) {
		ipv4 = (struct sockaddr_in *)res->ai_addr;
		inet_ntop(res->ai_family, ((void *)&(ipv4->sin_addr)), ip_n, ip_n_len);
		addr_r = ipv4->sin_addr.s_addr;
	}
	freeaddrinfo(res);

	return addr_r;
}

int getIfHwAddr(char *devname, char *mac)
{
	int skfd;
	int ret = -1;
	struct ifreq ifr;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return ret;

	strcpy(ifr.ifr_name, devname);
	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) != -1) {
		memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
		ret = 0;
	}
	close(skfd);

	return ret;
}

void get_sys_ver(char *v, int len)
{
	char buf[20];

	yfcat("/etc/version", "%s %*s %*s %*s %*s", buf);
	ydespaces(buf);
	snprintf(v, len-1, "%s", buf);
}

char *read_line(char *p, char *out, int maxlen)
{
	int c;
	char *e;

	if (p == NULL)
		return NULL;

	/* skip leading white spaces */
	while (*p && isspace(*p))
		p++;

	if (*p == '\0')
		return NULL;

	for (e = (out + maxlen - 1); (c = *p) && (out < e); p++) {
		switch (c) {
		case '\n':
			*out = 0;
			return ++p;
		case '\r':
			if (p[1] == '\n') {
				*out = 0;
				return &p[2];
			}
		// fall thru
		default:
			*out++ = c;
			break;
		}
	}
	*out = 0;

	return p;
}

/* This routine is needed due to SIGALRM received sometimes
**  when we use sleep() function instead.
*/
int my_sleep(int sec)
{
	int s;
	fd_set fdset;
	struct timeval  tm;
	int n;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return (sleep(sec));

	FD_ZERO(&fdset);
	FD_SET(s, &fdset);
	tm.tv_sec = sec;
	tm.tv_usec = 0;

	while (1) {
		if ((n = select(s + 1, &fdset, (fd_set *) NULL, (fd_set *) NULL, &tm)) < 0) {
			if (errno == EINTR)
				continue;
		}
		break;
	}
	close(s);
	return (0);
}

int my_sleep_msec(int msec)
{
	int s;
	fd_set fdset;
	struct timeval  tm;
	int n;
	unsigned long tmpsec, tmpmsec;

	if (msec <= 0)
		msec = 1000;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return usleep(msec*1000);

	FD_ZERO(&fdset);
	FD_SET(s, &fdset);
	tmpsec = msec / 1000;
	tmpmsec = msec % 1000;
	tm.tv_sec = tmpsec;
	tm.tv_usec = tmpmsec;

	while (1) {
		if ((n = select(s + 1, &fdset, (fd_set *) NULL, (fd_set *) NULL, &tm)) < 0) {
			if (errno == EINTR)
				continue;
		}
		break;
	}
	close(s);
	return (0);
}

void ether_toa(char *val, unsigned char *mac)
{
	int i = 0, n = 0;
	char tmp[40], buf[40];

	buf[0] = 0;
	while (val[i] != 0 && i < 12) {
		buf[i] = tolower(val[i]);
		i++;
	}
	buf[i] = '\0';
	if ((n = strspn(buf, "0123456789abcdef")) == 12) {
		n = 0;
		for (i=0; i<6; i++) {
			n += sprintf(tmp, "%.*s", 2, &buf[n]);
			mac[i] = strtoul(tmp, NULL, 16);
		}
	}
}

int write_pid(const char *pid_file)
{
	FILE *f;
	int pid = 0;

	if (!pid_file || !pid_file[0])
		return 0;

	if ((f = fopen(pid_file, "w"))) {
		pid = getpid();
		fprintf(f, "%d\n", pid);
		fclose(f);
	}
	return pid;
}

int test_pid(const char *pid_file)
{
	char path[64];
	int pid = read_pid(pid_file);

	if (pid <= 0)
		return 0;

	sprintf(path, "/proc/%d/cmdline", pid);
	return (access(path, F_OK) == 0) ? pid : 0;
}

int read_int(const char *file, int def)
{
	FILE *f;
	int ret = def;

	if (!file || !file[0])
		return ret;

	f = fopen(file, "r");
	if (f) {
		if (fscanf(f, "%d", &ret) != 1) {
			ret = def;
		}
		fclose(f);
	}
	return ret;
}

int strtoi(const char *s, int *ret)
{
	char *q;
	int saved_errno;

	if (!s || !s[0])
		return -1;
	saved_errno = errno;
	errno = 0;
	*ret = strtol(s, &q, 0);
	if (errno)
		return -1;
	if (s == q || !q || (*q && !isspace(*q))) {
		errno = EINVAL;
		return -1;
	}
	errno = saved_errno;
	return 0;
}

int safe_atoi(const char *s, int ndefault)
{
	int n;

	if (strtoi(s, &n))
		n = ndefault;
	return n;
}
