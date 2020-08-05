#include <sys/types.h>
#include <sys/select.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <nmpipe.h>

static const char *Laborer = "/var/laborer";

#define MAXLINE	1024

static int read_cnt;
static char *read_ptr;
static char read_buf[MAXLINE];

static void getcurrenttime(struct timeval *tvp)
{
	struct timespec ts;
	syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &ts);
	tvp->tv_sec = ts.tv_sec;
	tvp->tv_usec = ts.tv_nsec / 1000;
}

static ssize_t readchar(int fd, char *ptr)
{
	fd_set rdset;
	struct timeval current, expiry;

	if (read_cnt <= 0) {
		struct timeval tout = { .tv_sec = 5, .tv_usec = 0 };

		getcurrenttime(&current);
		timeradd(&current, &tout, &expiry);
 again:
		getcurrenttime(&current);
		if (timercmp(&current, &expiry, >))
			return 0;

		FD_ZERO(&rdset);
		FD_SET(fd, &rdset);

		switch (select(fd + 1, &rdset, NULL, NULL, &tout)) {
		default:
			read_cnt = read(fd, read_buf, sizeof(read_buf));
			if (read_cnt > 0)
				break;
			else if (read_cnt == 0)
				return 0;
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				goto again;
			return -1;
		case 0:
			return 0;
		}
		read_ptr = read_buf;
	}

	read_cnt--;
	*ptr = *read_ptr++;
	return (1);
}

static int fifo_response(const char *fifo)
{
	int n, fd;
	struct stat statf;

	if (fifo == NULL || fifo[0] == '\0')
		return -1;

	n = stat(fifo, &statf);
	if (n == 0) {
		if (unlink(fifo) < 0) {
			fprintf(stderr, "cannot delete old fifo (%s): %s\n",
				fifo, strerror(errno));
			return -1;
		}
	} else if (n < 0 && errno != ENOENT)
		fprintf(stderr, "FIFO stat failed: %s\n", strerror(errno));

	if (mkfifo(fifo, 0666) < 0)
		return -1;

	if ((fd = open(fifo, O_RDONLY | O_NONBLOCK)) < 0)
		return -1;

	return fd;
}

static int fifo_request(const char *path, const char *command)
{
	int rc, server = open(path, O_WRONLY | O_NONBLOCK);

	if (server < 0)
		return -1;
	rc = dprintf(server, ":%s:served_%d\n", command, getpid());
	close(server);
	return rc;
}

ssize_t presponse(struct nmpipe *p, void *vptr, size_t maxlen)
{
	ssize_t n, rc;
	char c, *ptr;

	ptr = vptr;
	for (n = 1; n < maxlen; n++) {
		if ((rc = readchar(p->fd, &c)) == 1) {
			*ptr++ = c;
			if (c == '\n')
				break;	/* newline is stored, like fgets() */
		} else if (rc == 0) {
			*ptr = 0;
			return (n - 1);	/* EOF, n - 1 bytes were read */
		} else
			return (-1);	/* error, errno set by read() */
	}

	*ptr = 0;		/* null terminate like fgets() */
	return (n);
}

struct nmpipe *prequest(const char *command)
{
	struct nmpipe *p;
	struct stat statf;

	if (stat(Laborer, &statf) ||
	    (!S_ISFIFO(statf.st_mode) && ( { errno = EINVAL; 1;}))) {
		fprintf(stderr, "%s: %s\n", Laborer, strerror(errno));
		return NULL;
	}
	p = (struct nmpipe *)malloc(sizeof(*p));
	sprintf(p->path, "/var/served_%d", getpid());
	p->fd = fifo_response(p->path);
	if (p->fd < 0) {
		free(p);
		return NULL;
	}

	if (fifo_request(Laborer, command) < 0) {
		perror(Laborer);
		close(p->fd);
		free(p);
		return NULL;
	}

	return p;
}

int prelease(struct nmpipe *p)
{
	if (p == NULL)
		return -1;
	if (p->fd > -1)
		close(p->fd);
	unlink(p->path);
	free(p);
	return 0;
}
