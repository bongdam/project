#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libytool.h>
#include "instrument.h"
#include "cmd.h"

#define CMD_SEPARATOR ':'

#define FIFO_REPLY_RETRIES 4
#define FIFO_REPLY_WAIT    80000

#define DEFAULT_FIFO_DIR            "/var/"
#define FIFO_DEFAULT_NAME           DEFAULT_FIFO_DIR "laborer"

/* ---- Private Function Prototypes -------------------------------------- */
/* ---- Private Variables ------------------------------------------------ */
/* ---- Public Variables ------------------------------------------------- */
char *fifo = FIFO_DEFAULT_NAME;
char *fifo_dir = DEFAULT_FIFO_DIR;	/* dir where reply fifos are allowed */

/* ---- Extern variables and function prototype -------------------------- */
/* ---- Functions -------------------------------------------------------- */

#define timer_cmp(a, b, CMP)                                            \
  (((a)->tv_sec == (b)->tv_sec) ?                                       \
   (((signed)(a)->tv_usec - (signed)(b)->tv_usec) CMP 0) :              \
   (((signed)(a)->tv_sec - (signed)(b)->tv_sec) CMP 0))

#ifdef THREAD_SAFE
static pthread_mutex_t itimerlist_lock = PTHREAD_MUTEX_INITIALIZER;
#define lock()		pthread_mutex_lock(&itimerlist_lock)
#define unlock()	pthread_mutex_unlock(&itimerlist_lock)
#else
#define lock()		do {} while (0);
#define unlock()	do {} while (0);
#endif

struct itimer_list {
	struct itimer_list *next;
	struct timeval expires, timeout;
	unsigned long data;
	int (*function)(long, unsigned long);
	long id;
};

static struct itimer_list *itimerlist_head;
static const struct timeval poll_granul = { 1, 0 };	/* 1/sec */
static const struct timeval split_sec = { 0, 1 };

void getcurrenttime(struct timeval *tvp)
{
	struct timespec ts;
	tvp->tv_sec = ygettime(&ts);
	tvp->tv_usec = ts.tv_nsec / 1000;
}

static inline void __itimer_insert(struct itimer_list *itimer, long id)
{
	struct itimer_list **c;

	itimer->id = id;
	for (c = &itimerlist_head; c[0]; c = &c[0]->next) {
		if (timercmp(&itimer->expires, &c[0]->expires, <))
			break;
	}
	itimer->next = c[0];
	c[0] = itimer;
}

int itimer_cancel(long tid, int (*function)(unsigned long))
{
	struct itimer_list **c;
	struct itimer_list *itimer = NULL;
	unsigned long data;

	if (tid == 0)
		return -1;

	lock();
	for (c = &itimerlist_head; c[0] != NULL; c = &c[0]->next) {
		if (c[0]->id == tid) {
			itimer = c[0];
			c[0] = itimer->next;
			data = itimer->data;
			free(itimer);
			break;
		}
	}
	unlock();

	if (itimer && function)
		function(data);

	return (itimer) ? 0 : -1;
}

int itimer_creat(unsigned long data,
		 int (*function)(long, unsigned long), struct timeval *timeout)
{
	static long mono_allocator;
	struct itimer_list *itimer;
	struct timeval base;

	if (!function)
		return 0;

	itimer = (struct itimer_list *)malloc(sizeof(struct itimer_list));
	if (itimer == NULL)
		return 0;

	itimer->next = NULL;
	itimer->data = data;
	itimer->function = function;
	if (!++mono_allocator)
		mono_allocator = 1;

	getcurrenttime(&base);
	timeradd(&base, timeout, &itimer->expires);
	itimer->timeout = *timeout;

	lock();

	__itimer_insert(itimer, mono_allocator);

	unlock();

	return itimer->id;
}

struct timeval *itimer_iterate(struct timeval *tvp)
{
	struct timeval tv;
	struct itimer_list *c;
	int res;

	*tvp = poll_granul;

	lock();
	if (itimerlist_head != NULL) {
		getcurrenttime(&tv);
		do {
			if (timer_cmp(&itimerlist_head->expires, &tv, <=)) {
				c = itimerlist_head;
				itimerlist_head = c->next;
				/*
				 * At this point, the schedule queue is still intact.  We
				 * have removed the first event and the rest is still there,
				 * so it's permissible for the function to add new events, but
				 * trying to delete itself won't work because it isn't in
				 * the schedule queue.  If that's what it wants to do, it
				 * should return 0.
				 */
				unlock();

				res = c->function(c->id, c->data);

				lock();
				if (res) {
					timeradd(&tv, &c->timeout, &c->expires);
					__itimer_insert(c, c->id);
				} else
					free(c);
			} else
				break;
		} while (itimerlist_head != NULL);

		if (itimerlist_head != NULL) {
			timersub(&itimerlist_head->expires, &tv, tvp);
			if (timer_cmp(tvp, &poll_granul, >))
				*tvp = poll_granul;
			else if (timer_cmp(tvp, &split_sec, <=))
				*tvp = split_sec;
		}
	}
	unlock();

	return tvp;
}

void itimer_flush(void)
{
	struct itimer_list *c;

	lock();
	while (itimerlist_head != NULL) {
		c = itimerlist_head;
		itimerlist_head = c->next;
		free(c);
	}
	unlock();
}

static inline void sleep_us(unsigned int nusecs)
{
	struct timeval tval;
	tval.tv_sec = nusecs / 1000000;
	tval.tv_usec = nusecs % 1000000;
	select(0, NULL, NULL, NULL, &tval);
}

static char *trim_filename(char *file)
{
	int prefix_len, fn_len;
	char *new_fn;

	/* we only allow files in "/tmp" -- any directory
	   changes are not welcome
	 */
	if (strchr(file, '.') || strchr(file, '/')
	    || strchr(file, '\\')) {
		fprintf(stderr, "trim_filename: forbidden filename: %s\n", file);
		return NULL;
	}
	prefix_len = strlen(fifo_dir);
	fn_len = strlen(file);
	new_fn = malloc(prefix_len + fn_len + 1);
	if (new_fn == NULL) {
		fprintf(stderr, "trim_filename: no mem\n");
		return NULL;
	}

	memcpy(new_fn, fifo_dir, prefix_len);
	memcpy(new_fn + prefix_len, file, fn_len);
	new_fn[prefix_len + fn_len] = 0;

	return new_fn;
}

/* reply fifo security checks:
 * checks if fd is a fifo, is not hardlinked and it's not a softlink
 * opened file descriptor + file name (for soft link check)
 * returns 0 if ok, <0 if not */
static int fifo_check(int fd, char *fname)
{
	struct stat fst;
	struct stat lst;

	if (fstat(fd, &fst) < 0) {
		fprintf(stderr, "fstat failed: %s\n", strerror(errno));
		return -1;
	}
	/* check if fifo */
	if (!S_ISFIFO(fst.st_mode)) {
		fprintf(stderr, "%s is not a fifo\n", fname);
		return -1;
	}
	/* check if hard-linked */
	if (fst.st_nlink > 1) {
		fprintf(stderr, "security: %s is hard-linked %d times\n",
			fname, (unsigned)fst.st_nlink);
		return -1;
	}

	/* lstat to check for soft links */
	if (lstat(fname, &lst) < 0) {
		fprintf(stderr, "lstat failed: %s\n", strerror(errno));
		return -1;
	}
	if (S_ISLNK(lst.st_mode)) {
		fprintf(stderr, "security: %s is a soft link\n", fname);
		return -1;
	}
	/* if this is not a symbolic link, check to see if the inode didn't
	 * change to avoid possible sym.link, rm sym.link & replace w/ fifo race
	 */
	if ((lst.st_dev != fst.st_dev) || (lst.st_ino != fst.st_ino)) {
		fprintf(stderr, "security: inode/dev number differ"
			": %d %d (%s)\n", (int)fst.st_ino, (int)lst.st_ino, fname);
		return -1;
	}
	/* success */
	return 0;
}

int open_reply_pipe(char *pipe_name)
{
	int fd, retries = FIFO_REPLY_RETRIES;

	if (!pipe_name || *pipe_name == 0)
		return -1;
tryagain:
	/* open non-blocking to make sure that a broken client will not
	 * block the FIFO server forever */
	fd = open(pipe_name, O_WRONLY | O_NONBLOCK);
	if (fd == -1) {
		/* retry several times if client is not yet ready for getting
		   feedback via a reply pipe
		 */
		if (errno == ENXIO) {
			/* give up on the client - we can't afford server blocking */
			if (retries == 0) {
				fprintf(stderr, "open_reply_pipe: no client at %s\n",
					pipe_name);
				return 0;
			}
			sleep_us(FIFO_REPLY_WAIT);
			retries--;
			goto tryagain;
		}
		/* some other opening error */
		fprintf(stderr, "open_reply_pipe: open error (%s): %s\n",
			pipe_name, strerror(errno));
		return -1;
	}

	/* security checks: is this really a fifo?, is
	 * it hardlinked? is it a soft link?
	 * & we want server blocking for big writes */
	if (fifo_check(fd, pipe_name) < 0) {
		close(fd);
		return -1;
	}

	if (!fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK))
		return fd;
	else
		perror("fcntl");
	close(fd);
	return -1;
}

/* tell FIFO client what happened via reply pipe */
void fifo_reply(char *reply_fifo, char *fmt, ...)
{
	int fd, r;
	va_list ap;

	if (!reply_fifo || *reply_fifo == 0)
		return;

	fd = open_reply_pipe(reply_fifo);
	if (fd < 0)
		return;
 retry:
	va_start(ap, fmt);
	r = vdprintf(fd, fmt, ap);
	va_end(ap);
	if (r <= 0) {
		fprintf(stderr, "write error (%s): %s\n",
			fifo, strerror(errno));
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			goto retry;
	}
	close(fd);
}

static int fifo_parse_line(char *buf)
{
	char *p, *command, *file = NULL;
	int len, rc;

	ydespaces(buf);
	len = strlen(buf);
	if (len < 3) {
		fprintf(stderr, "command must have at least 3 chars: %.*s\n",
			len, buf);
		return -1;
	}
	if (buf[0] != CMD_SEPARATOR) {
		fprintf(stderr, "command must begin with %c: %.*s\n",
			CMD_SEPARATOR, len, buf);
		return -1;
	}

	command = &buf[1];
	p = strchr(command, CMD_SEPARATOR);
	if (p == NULL || p == command) {
		fprintf(stderr, "file separator missing or empty\n");
		return -1;
	}

	if (*(p + 1)) {
		file = p + 1;
		file = trim_filename(file);
		if (file == 0) {
			fprintf(stderr, "trimming filename\n");
			return -1;
		}
	}
	/* make command zero-terminated */
	*p = 0;
	rc = fifo_handle_line(command, file);
	if (file)
		free(file);

	return rc;
}

int fifo_server(int fd, struct dline *dl)
{
	int rc, len = (int)(&dl->buf[MAXLINE] - dl->cp);

	if (len <= 0) {
		/* command too long to be handled. just consume */
		len = dline_reset(dl);
	}

	while (1) {
		rc = read(fd, dl->cp, len);
		if (rc <= 0) {
			if (errno == EINTR)
				continue;
			else if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -1;
		} else if (rc == 0)
			return -1;
		break;
	}

	for (dl->cp += rc; dl->p != dl->cp; ) {
		if (*dl->p++ == '\n') {
			dl->p[-1] = '\0';
			fifo_parse_line(dl->buf);
			if (dl->p == dl->cp)
				dline_reset(dl);
			else {
				memmove(dl->buf, dl->p, (len = (int)(dl->cp - dl->p)));
				dl->p = dl->buf;
				dl->cp = &dl->buf[len];
			}
		}
	}

	return 1;
}

int init_fifo_server(void)
{
	int n, fd, fifowr;
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

	fifowr = open(fifo, O_WRONLY | O_NONBLOCK);
	if (fifowr < 0) {
		close(fd);
		return -1;
	}
	/* set read fifo blocking mode */
	//if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK) < 0) {
	//	close(fd);
	//	return -1;
	//}

	return fd;
}
