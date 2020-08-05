#ifndef _instrument_h_
#define _instrument_h_

#include <sys/time.h>
#include <time.h>
#include <stdarg.h>

int itimer_cancel(long tid, int (*function)(unsigned long));
int itimer_creat(unsigned long data,
		 int (*function)(long, unsigned long),
		 struct timeval *timeout);
struct timeval *itimer_iterate(struct timeval *tvp);
void itimer_flush(void);

#define	MAXLINE	16384	/* max #bytes that a client can request */

struct dline {
	char *p, *cp;
	char buf[MAXLINE];
};

static inline int dline_reset(struct dline *d)
{
	d->p = d->cp = d->buf;
	return MAXLINE;
}

int init_fifo_server(void);
int fifo_server(int fd, struct dline *dl);
int open_reply_pipe(char *pipe_name);
void fifo_reply(char *reply_fifo, char *fmt, ...);

int nvram_get_int(char *name, int dft);

#endif	/* _instrument_h_ */
