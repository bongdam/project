#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/syslog.h>
#include <time.h>
#include "tlogin.h"
#include <bcmnvram.h>
#include "libytool.h"
#include <libkcapi.h>

#define MAX_STR_LEN 40
#define TIMEOUT  60
#define FAIL_DELAY 3

#define UNUSED(x) x=x

static void alarm_handler(int sig)
{
	UNUSED(sig);

	fprintf(stderr, "\nLogin timed out after %d seconds.\n", TIMEOUT);
	exit(0);
}

static char *cal_sha256(char *src, char *dest)
{
	const char *__xascii = "0123456789abcdef";
	unsigned char md[32];
	char *p;
	int i, c;

	c = strlen(src);
	posix_memalign((void **)&p, sysconf(_SC_PAGESIZE), c);
	memcpy(p, src, c);
	kcapi_md_sha256((uint8_t *)p, c, md, 32);
	free(p);

	p = dest;
	for (i = 0; i < (sizeof(md) / sizeof(md[0])); i++) {
		c = md[i];
		*p++ = __xascii[(c >> 4) & 0xf];
		*p++ = __xascii[c & 0xf];
	}
	*p = '\0';
	return dest;
}

static int doing_auth(char *u, char *p)
{
	char root_id[128], root_pw[128];
	char sha256_user[128] = {0,}, sha256_pass[128] = {0,};

	memset(root_id, 0, sizeof(root_id));
	memset(root_pw, 0, sizeof(root_pw));

	nvram_get_r_def("SUPER_NAME", root_id, sizeof(root_id), "");
	nvram_get_r_def("SUPER_PASSWORD", root_pw, sizeof(root_pw), "");

	cal_sha256(u, sha256_user);
	cal_sha256(p, sha256_pass);

	if (!strcmp(sha256_user, root_id)) {
		if (!strcmp(sha256_pass, root_pw)) {
			return 1;
		} else {
			return 0;
		}
	}

	nvram_get_r_def("factory_user", root_id, sizeof(root_id), "");
	nvram_get_r_def("factory_pw", root_pw, sizeof(root_pw), "");

	if (!strcmp(sha256_user, root_id)) {
		if (!strcmp(sha256_pass, root_pw)) {
			return 1;
		} else {
			return 0;
		}
	}

	return 0;
}

/* do nothing signal handler */
static void askpass_timeout(int ignore)
{
	UNUSED(ignore);
}

static char *tbb_askpass(int timeout, const char *prompt)
{
	char *ret;
	int i, size;
	struct sigaction sa;
	struct termios old, new;
	static char passwd[MAX_STR_LEN];

	tcgetattr(STDIN_FILENO, &old);

	size = sizeof(passwd);
	ret = passwd;
	memset(passwd, 0, size);

	fputs(prompt, stdout);
	fflush(stdout);

	tcgetattr(STDIN_FILENO, &new);
	new.c_iflag &= ~(IUCLC | IXON | IXOFF | IXANY);
	new.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | TOSTOP);
	tcsetattr(STDIN_FILENO, TCSANOW, &new);

	if (timeout) {
		sa.sa_flags = 0;
		sa.sa_handler = askpass_timeout;
		sigaction(SIGALRM, &sa, NULL);
		alarm(timeout);
	}

	if (read(STDIN_FILENO, passwd, size - 1) <= 0) {
		ret = NULL;
	} else {
		for (i = 0; i < size && passwd[i]; i++) {
			if (passwd[i] == '\r' || passwd[i] == '\n') {
				passwd[i] = 0;
				break;
			}
		}
	}

	if (timeout) {
		alarm(0);
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &old);
	fputs("\n", stdout);
	fflush(stdout);
	return ret;
}

static int login_prompt(char *u, int sz)
{
	int i;
	char buf[MAX_STR_LEN];
	char *sp, *ep;

    /* to pass RFI test on LG-Dacom BMT, it should be used for testing */
    printf("DVW-2700 (AP router) System\n\n");

	for (i=0; i<3; i++) {
		printf("Login: "); fflush(stdout);
		if (!fgets(buf, MAX_STR_LEN-1, stdin))
			return 0;
		if (!strchr(buf, '\n'))
			return 0;
		for (sp=buf; isspace(*sp); sp++)
			;
		for (ep=sp; isgraph(*ep); ep++)
			;
		*ep = 0;
		memset(u, 0, sz);
		strncpy(u, sp, sz);
		if (u[0])
			return 1;
	}
	return 0;
}

static int get_password(char *p, int sz)
{
	char *pass;

	pass = tbb_askpass(0, "Password: ");
	if (!pass)
		return 0;
	strncpy(p, pass, sz);
	return 1;
}



int tlogin_main(char *login_ip)
{
	int alarmstarted = 0;
	int count = 0;
	char username[MAX_STR_LEN], password[MAX_STR_LEN];
   	time_t     current_time;
   	struct tm *struct_time;
	char timeBuf[40];

	signal(SIGALRM, alarm_handler);
	alarm(TIMEOUT);
	alarmstarted = 1;

	while (1) {
		if (!login_prompt(username, MAX_STR_LEN)) {
			return -1;
		}

		if (!alarmstarted && (TIMEOUT > 0)) {
			alarm(TIMEOUT);
			alarmstarted = 1;
		}

		if (!get_password(password, MAX_STR_LEN)) {
			return -2;
		}

		if (doing_auth(username, password)) {
#if defined(CONFIG_OEM_CJHV)
			syslog(LOG_INFO, "telnetd login successfully from %s.", login_ip);
			//attack_ipaddress time check
			time(&current_time);
			struct_time = localtime( &current_time);
			sprintf(timeBuf, "%04d-%02d-%02d %02d:%02d:%02d", struct_time->tm_year+1900, struct_time->tm_mon+1, struct_time->tm_mday,
													struct_time->tm_hour, struct_time->tm_min, struct_time->tm_sec);
			yfecho("/tmp/attack_ip", O_WRONLY|O_CREAT|O_TRUNC, 0644, "%s %s", login_ip, timeBuf);
#endif
			break; 	// auth success
		}
#if defined(CONFIG_OEM_CJHV)
		syslog(LOG_INFO, "telnetd login failed from %s.", login_ip);
#endif
#if 1
		sleep(FAIL_DELAY);
#else
		{ // delay next try
			time_t start, now;
			time(&start);
			now = start;
			while (difftime(now, start) < FAIL_DELAY) {
				sleep(FAIL_DELAY);
				time(&now);
			}
		}
#endif
		puts("Login incorrect");
		username[0] = 0;
		if (++count == 3) {
			return -3;
		}
	}

	alarm(0);
	return 1;
}
