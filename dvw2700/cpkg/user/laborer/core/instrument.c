#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <libytool.h>
#include <bcmnvram.h>
#include "notice.h"
#include "instrument.h"

/* ---- Private Function Prototypes -------------------------------------- */
/* ---- Private Variables ------------------------------------------------ */
/* ---- Public Variables ------------------------------------------------- */
/* ---- Extern variables and function prototype -------------------------- */
/* ---- Functions -------------------------------------------------------- */

int notice_chain_register(struct notice_block **nl, struct notice_block *n)
{
	while ((*nl) != NULL) {
		/* the bigger is the higher */
		if (n->priority > (*nl)->priority)
			break;
		nl = &((*nl)->next);
	}
	n->next = *nl;
	*nl = n;
	return 0;
}

int notice_chain_deregister(struct notice_block **nl, struct notice_block *n)
{
	if (n == NULL)
		return -1;
	while (*nl && *nl != n)
		nl = &((*nl)->next);
	if (*nl == n)
		*nl = n->next;
	return 0;
}

int notice_call_chain(struct notice_block **nl,
		u_int event, u_int full_event, int nr_to_call)
{
	int ret = NOTICE_DONE;
	struct notice_block *nb, *next_nb;

	for (nb = *nl; nb && nr_to_call; nr_to_call--, nb = next_nb) {
		next_nb = nb->next;

		if ((event & nb->concern) == 0)
			continue;

		ret = nb->notice_call(nb, event, full_event);
		if ((ret & NOTICE_STOP_MASK) == NOTICE_STOP_MASK)
			break;
	}
	return ret;
}

int nvram_get_int(char *param, int dft)
{
	char *p = nvram_get(param);
	return (p && p[0]) ? atoi(p) : dft;
}

void diag_printf(const char *format, ...)
{
	va_list ap;
	struct timeval now;
	struct tm *ptm;

	gettimeofday(&now, NULL);
	ptm = localtime(&now.tv_sec);
	fprintf(stdout, "[%02d:%02d:%02d.%03ld] ",
		ptm->tm_hour, ptm->tm_min, ptm->tm_sec, now.tv_usec / 1000);
	va_start(ap, format);
	vfprintf(stdout, format, ap);
	va_end(ap);
}

int dispatch_event(unsigned int setbits, unsigned int mask, int overwrite)
{
	int fd;
	u_int32_t curr, cmd[2] = { [0] = setbits, [1] = mask };

	fd = open("/proc/dvflag", O_RDWR);
	if (fd != -1) {
		safe_read(fd, (void *)&curr, sizeof(curr));
		if (overwrite || ((curr & mask) ^ setbits))
			write(fd, cmd, sizeof(cmd));
		close(fd);
		return (curr & mask);
	}
	return 0;
}

size_t strlcpy(char *dst, const char *src, size_t n)
{
	const char *src0 = src;
	char dummy[1];

	if (!n)
		dst = dummy;
	else
		--n;

	while ((*dst = *src) != 0) {
		if (n) {
			--n;
			++dst;
		}
		++src;
	}

	return src - src0;
}

int fget_and_test_pid(const char *filename)
{
	int pid;
	if (yfcat(filename, "%d", &pid) != 1 || kill(pid, 0))
		pid = 0;
	return pid;
}

char *strlfcat(char *dest, size_t n, const char *fmt, ...)
{
	va_list ap;
	size_t len = strlen(dest);

	if (len < n) {
		va_start(ap, fmt);
		vsnprintf(dest + len, n - len, fmt, ap);
		va_end(ap);
	}
	return dest;
}

char *strdupr(char *s, const char *t)
{
	free(s);
	return t ? strdup(t) : NULL;
}

static inline int str_grow(struct str *s)
{
	char *q;
	if (s->size == 0)
		s->size = 80;
	q = realloc(s->p, s->size << 1);
	if (q) {
		s->p = q;
		s->size <<= 1;
		return 0;
	}
	return -1;
}

int str_putc(int c, struct str *s)
{
	if ((s->pos + 1) >= s->size && str_grow(s))
		return -1;
	s->p[s->pos++] = c;
	return 0;
}

int str_printf(struct str *m, const char *f, ...)
{
	va_list ap, aq;
	int len;

	if (m == NULL || m->p == NULL)
		return -1;

	va_start(ap, f);
	va_copy(aq, ap);
	len = vsnprintf(m->p + m->pos, m->size - m->pos, f, aq);
	va_end(aq);

	if (len >= (m->size - m->pos)) {
		char *p = realloc(m->p, (len + m->pos) << 1);
		if (p) {
			m->p = p;
			m->size = (len + m->pos) << 1;
			len = vsnprintf(m->p + m->pos, m->size - m->pos, f, ap);
		} else
			len = (m->size - m->pos) - 1;
	}
	va_end(ap);
	m->pos += len;
	return len;
}

int select_event_fdset_dfl(struct select_event_base *base, fd_set *rset, fd_set *wset)
{
	FD_SET(base->fd, rset);
	return base->fd;
}
