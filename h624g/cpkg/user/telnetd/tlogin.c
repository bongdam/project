#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <crypt.h>
#include <sys/types.h>
#include <pwd.h>
#include <limits.h>
#include "tlogin.h"

#define MAX_STR_LEN 40
#define TIMEOUT  60
#define FAIL_DELAY 3

#define UNUSED(x) (x) = (x)

extern char *crypt(const char *key, const char *salt);

static void alarm_handler(int sig)
{
	UNUSED(sig);

	fprintf(stderr, "\nLogin timed out after %d seconds.\n", TIMEOUT);
	exit(0);
}

static int doing_auth(char *u, char *p, char *buf, size_t n)
{
	struct passwd *pwp;
	int good;

	if (!u || !u[0] || !p || !p[0])
		return 0;
	pwp = getpwnam(u);
	if (pwp == NULL)
		return 0;
	good = strcmp(pwp->pw_passwd, crypt(p, "$1$")) ? 0 : 1;
	if (good) {
		snprintf(buf, n, "%s", pwp->pw_shell);
		setuid(pwp->pw_uid);
	}
	return good;
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
	char host[HOST_NAME_MAX];
	char buf[MAX_STR_LEN];
	char *sp, *ep;

	if (gethostname(host, sizeof(host)))
		strcpy(host, "Wireless");
	for (i = 0; i < 3; i++) {
		printf("%s login: ", host);
		fflush(stdout);
		if (!fgets(buf, MAX_STR_LEN - 1, stdin))
			return 0;
		if (!strchr(buf, '\n'))
			return 0;
		for (sp = buf; isspace(*sp); sp++) ;
		for (ep = sp; isgraph(*ep); ep++) ;
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

const char *tlogin_main(void)
{
	static char rshell[64];
	int alarmstarted = 0;
	int count = 0;
	char username[MAX_STR_LEN], password[MAX_STR_LEN];

	signal(SIGALRM, alarm_handler);
	alarm(TIMEOUT);
	alarmstarted = 1;

	while (1) {
		if (!login_prompt(username, MAX_STR_LEN))
			return NULL;

		if (!alarmstarted && (TIMEOUT > 0)) {
			alarm(TIMEOUT);
			alarmstarted = 1;
		}

		if (!get_password(password, MAX_STR_LEN))
			return NULL;

		if (doing_auth(username, password, rshell, sizeof(rshell)))
			break;	// auth success
#if 1
		sleep(FAIL_DELAY);
#else
		{		// delay next try
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
		if (++count == 3)
			return NULL;
	}

	alarm(0);
	return rshell;
}
