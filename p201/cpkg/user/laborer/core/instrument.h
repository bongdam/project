#ifndef _instrument_h_
#define _instrument_h_

#include <time.h>
#include <libytool.h>
#include <select_event.h>
#include <itimer.h>
#include "fifoserve.h"
#include "cmd.h"

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#ifndef _NDEBUG
#define DIAG(arg...) \
	do {\
		if (verbose) \
			diag_printf(arg);\
	} while (0)
#else
#define DIAG(arg...) do {} while (0)
#endif

static inline ssize_t safe_read(int fd, void *buf, size_t count)
{
	ssize_t n;

	do n = read(fd, buf, count);
	while (n < 0 && errno == EINTR);
	return n;
}

void diag_printf(const char *format, ...);
int dispatch_event(unsigned int setbits, unsigned int mask, int overwrite);
size_t strlcpy(char *dst, const char *src, size_t n);
int fget_and_test_pid(const char *filename);
char *strlfcat(char *dest, size_t n, const char *fmt, ...);
int select_event_fdset_dfl(struct select_event_base *base, fd_set *rset, fd_set *wset);

struct str {
	char *p;
	size_t size;
	int pos;
};

int str_putc(int, struct str *);
int str_printf(struct str *, const char *, ...);

#endif	/* _instrument_h_ */
