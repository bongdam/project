#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "instrument.h"

#define CMD_SEPARATOR ':'

#define FIFO_REPLY_RETRIES	4
#define FIFO_REPLY_WAIT		80000

#define DEFAULT_FIFO_DIR	"/var/"
#define FIFO_DEFAULT_NAME	DEFAULT_FIFO_DIR "laborer"

#define	MAXLINE	16384	/* max #bytes that a client can request */

struct reqline {
	char *p, *cp;
	char buf[MAXLINE];
};
/* ---- Private Function Prototypes -------------------------------------- */
/* ---- Private Variables ------------------------------------------------ */
/* ---- Public Variables ------------------------------------------------- */
char *fifo = FIFO_DEFAULT_NAME;
char *fifo_dir = DEFAULT_FIFO_DIR;	/* dir where reply fifos are allowed */

/* ---- Extern variables and function prototype -------------------------- */
/* ---- Functions -------------------------------------------------------- */

static inline int reqline_reset(struct reqline *d)
{
	d->p = d->cp = d->buf;
	return MAXLINE;
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

	return fd;
}

/* tell FIFO client what happened via reply pipe */
void fifo_reply(int fd, char *fmt, ...)
{
	va_list ap;
	int r;
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

#define fifo_server_fdset select_event_fdset_dfl

static int fifo_server_read(struct select_event_base *base, int fd)
{
	struct reqline *reql = (struct reqline *)base->data;
	int bytes, len = (int)(&reql->buf[MAXLINE] - reql->cp);

	if (len <= 0)
		/* command too long to be handled. just consume */
		len = reqline_reset(reql);

	for (;;) {
		bytes = safe_read(fd, reql->cp, len);
		if (bytes < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -1;
		} else if (bytes == 0)
			return -1;
		break;
	}

	for (reql->cp += bytes; reql->p != reql->cp; ) {
		if (*reql->p++ == '\n') {
			reql->p[-1] = '\0';
			fifo_parse_line(reql->buf);
			if (reql->p == reql->cp)
				reqline_reset(reql);
			else {
				memmove(reql->buf, reql->p, (len = (int)(reql->cp - reql->p)));
				reql->p = reql->buf;
				reql->cp = &reql->buf[len];
			}
		}
	}

	return bytes;
}

static int fifo_server_close(struct select_event_base *base, int fd)
{
	if (base->data)
		free(base->data);
	return 0;
}

static struct select_event_operation op = {
	._fdset = fifo_server_fdset,
	._read = fifo_server_read,
	._close = fifo_server_close,
};

static void __attribute__ ((constructor)) init_fifo_server(void)
{
	int n, fd, fifowr;
	struct stat statf;
	struct reqline *reql;

	if (fifo == NULL || fifo[0] == '\0')
		return;

	n = stat(fifo, &statf);
	if (n == 0) {
		if (unlink(fifo) < 0) {
			fprintf(stderr, "cannot delete old fifo (%s): %s\n",
				fifo, strerror(errno));
			return;
		}
	} else if (n < 0 && errno != ENOENT)
		fprintf(stderr, "FIFO stat failed: %s\n", strerror(errno));

	if (mkfifo(fifo, 0666) < 0)
		perror("mkfifo");
	else if ((fd = open(fifo, O_RDONLY | O_NONBLOCK)) < 0)
		perror("open_ro");
	else if ((fifowr = open(fifo, O_WRONLY | O_NONBLOCK)) < 0) {
		close(fd);
		perror("open_wo");
	} else {
		/* set read fifo blocking mode */
		/*if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK) < 0) {
			close(fd);
			return;
		}*/
		reql = (struct reqline *)malloc(sizeof(struct reqline));
		reqline_reset(reql);

		select_event_alloc(fd, &op, reql, "fifo://%s", fifo[0] == '/' ? &fifo[1] : fifo);
	}
}
