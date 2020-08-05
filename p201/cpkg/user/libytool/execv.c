#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>

extern void yclosefrom(int lowfd);
extern char **__environ;
#ifndef uninitialized_var
#define uninitialized_var(x) x = x
#endif

#define TEMP_FAILURE_RETRY(expression) \
  (__extension__                                        \
    ({ long int __result;                               \
       do __result = (long int) (expression);           \
       while (__result == -1L && errno == EINTR);       \
       __result; }))

#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))
#define isdigit(c) (((unsigned int)((c) - 48)) <= (57 - 48))

enum { EBLANK, EFROM, ETO, ETOFD };

static int is_digit(int c)
{
	return isdigit(c);
}

static int is_noblank(int c)
{
	return !isspace(c) && (c != '>') && (c != '&') && (c != '|');
}

static int expfname(const char **command, char *path, int (*isgood)(int))
{
	const char *s = *command;
	char *d = path;
	int c;

	while ((c = *s) && isgood(c))
		*d++ = *s++;
	*d = '\0';
	*command = --s;
	return (int)(d - path);
}

static int strfno(const char *p, int *fd)
{
	if (strspn(p, "1234567890") != strlen(p))
		return -1;
	if (fd)
		*fd = strtoul(p, NULL, 10);
	return 0;
}

static int dupredirect(char *from, char *to, int flags, int state)
{
	int ffd, tfd, fd;

	if (strfno(from, &ffd))
		return -1;

	if (state == ETOFD) {
		if (strfno(to, &tfd))
			return -1;
		if (ffd == tfd)
			return 0;
		if ((fd = dup2(tfd, ffd)) < 0)
			perror(to);
	} else {
		if ((fd = open(to, flags, 0644)) < 0)
			perror(to);
		else {
			dup2(fd, ffd);
			close(fd);
		}
	}
	return (fd != -1) ? 0 : -1;
}

static int redir_output(const char *command)
{
	char from[12], to[PATH_MAX];
	int state, c, uninitialized_var(flags);

	for (state = EBLANK; (c = *command); command++) {
		switch (state) {
		case EBLANK:
			if (isspace(c))
				break;
			strcpy(from, "1");
			flags = O_WRONLY | O_CREAT | O_TRUNC;
			state = EFROM;
		case EFROM:
			if (c == '>') {
				state = ETO;
				c = *++command;
				if (c == '>')
					flags = O_WRONLY | O_CREAT | O_APPEND;
				else if (c == '&')
					state = ETOFD;
				else
					--command;
			} else if (!isdigit(c) ||
				   !expfname(&command, from, is_digit))
				return -1;
			break;
		case ETO:
			while (isspace(c))
				c = *++command;
		case ETOFD:
			if (!expfname(&command, to,
				      (state == ETO) ? is_noblank : is_digit))
				return -1;
			if (dupredirect(from, to, flags, state))
				return -1;
			state = EBLANK;
			break;
		default:
			return -1;
		}
	}

	return 0;
}

int yexecv(char *const argv[], char *path, int timeout, int *ppid)
{
	pid_t pid;
	sigset_t mask, orig_mask;

	sigemptyset(&mask);
	if (!ppid && timeout > 0) {
		sigaddset(&mask, SIGCHLD);
	 	if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) < 0)
			return -1;
	}

	pid = fork();
	if (pid == 0) {
		char **new_environ, **ep;
		int sig, size;

		/* Reset signal handlers set for parent process */
		for (sig = 0; sig < (_NSIG - 1); sig++)
			signal(sig, SIG_DFL);

		/* Clean up */
		ioctl(0, TIOCNOTTY, 0);
		yclosefrom(STDERR_FILENO + 1);
		setsid();

		/* Redirect stdout to <path> */
		if (path)
			redir_output(path);

		size = 0;
		for (ep = __environ; ep && *ep; ep++) {
			if (!strncmp(*ep, "PATH=", sizeof("PATH=") - 1))
				goto PATH_SET;
			size++;
		}

		new_environ = alloca((size + 2) * sizeof(char *));
		if (new_environ == NULL)
			_exit(errno);
		memcpy(new_environ, __environ, size * sizeof(char *));
		__environ = new_environ;
		ep = &new_environ[size];
		ep[1] = NULL;
PATH_SET:
		ep[0] = "PATH=/bin:/usr/sbin:/usr/bin:/sbin";

		alarm(ppid ? timeout : 0);
		execvp(argv[0], argv);
		perror(argv[0]);
		exit(errno);
	} else if (pid > 0) {
		int status;

		if (ppid) {
			*ppid = pid;
			return 0;
		} else if (timeout > 0) {
			struct timespec ts = { .tv_sec = timeout, .tv_nsec = 0 };
			while (sigtimedwait(&mask, NULL, &ts) < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN)
					kill(pid, SIGKILL);
				break;
			}
			sigprocmask(SIG_SETMASK, &orig_mask, NULL);
		}

		if (TEMP_FAILURE_RETRY(waitpid(pid, &status, 0)) != pid)
			return (errno != ECHILD) ? -1 : 0;
		return status;
	} else if (sigismember(&mask, SIGCHLD) == 1)
		sigprocmask(SIG_SETMASK, &orig_mask, NULL);

	return -1;
}
