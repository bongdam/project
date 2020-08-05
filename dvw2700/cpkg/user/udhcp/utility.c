#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include "debug.h"

static void get_mono(struct timespec *ts)
{
	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, ts))
		perror("clock_gettime(MONOTONIC) failed");
}

unsigned monotonic_ms(void)
{
	struct timespec ts;
	get_mono(&ts);
	return (unsigned)(ts.tv_sec * 1000UL + ts.tv_nsec / 1000000);
}

unsigned getmonotime(struct timeval *tvp)
{
	struct timespec ts;
	get_mono(&ts);
	if (tvp) {
		tvp->tv_sec = ts.tv_sec;
		tvp->tv_usec = ts.tv_nsec / 1000;
	}
	return ts.tv_sec;
}

char *ether_ntoa(unsigned char *haddr)
{
	static char buffer[32];

	sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
		haddr[0], haddr[1], haddr[2],
		haddr[3], haddr[4], haddr[5]);
	return buffer;
}

char *dewhites(char *s)
{
	char *p, *q;
	int c;

	/* skip leading spaces */
	for (p = s; (c = *p) && isspace(c); p++) ;
	/* run to the end of string */
	for (q = p; *q; c = *q++) ;
	for (q--; isspace(c); c = *q)
		*q-- = '\0';
	if (p != s) {
		for (q = s; *p; *q++ = *p++) ;
		*q = 0;
	}
	return s;
}

static int vcbprintf(struct cbuffer *m, const char *f, va_list args)
{
	size_t len;

	while (m->count < m->size) {
		len = (size_t)vsnprintf(m->buf + m->count, m->size - m->count, f, args);
		if (len < (m->size - m->count)) {
			m->count += len;
			return 0;
		} else {
			char *p = realloc(m->buf, len + m->count + 1);
			if (!p)
				break;
			m->buf = p;
			m->size = len + m->count + 1;
		}
	}

	m->count = m->size;
	return -1;
}

int cbprintf(struct cbuffer *m, const char *f, ...)
{
	int status;
	va_list args;

	va_start(args, f);
	status = vcbprintf(m, f, args);
	va_end(args);
	return status;
}

void nnull_pad(struct double_null_cbuf *nnull)
{
	cbprintf(&nnull->cb, " ");
	nnull->cb.buf[nnull->cb.count - 1] = '\0';
	nnull->argc += 1;
}

int nnull_printf(struct double_null_cbuf *nnull, const char *f, ...)
{
	va_list args;
	int status;

	va_start(args, f);
	status = vcbprintf(&nnull->cb, f, args);
	va_end(args);
	if (!status && nnull->cb.count < nnull->cb.size)
		nnull_pad(nnull);
	return status;
}
