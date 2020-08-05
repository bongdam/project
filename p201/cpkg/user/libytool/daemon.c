#include <stdlib.h>
#include <string.h>
#include "libytool.h"

static inline void
strpull(char *dest, size_t dlen, const char *src, size_t slen)
{
	memmove(dest + slen, dest, dlen + 1);
	memcpy(dest, src, slen);
}

int ydaemon(int nochdir, int noclose, const char *fmt, ...)
{
	char *argv[4] = { "sh", "-c", NULL, NULL };
	va_list ap;
	char buf[128], *p;
	int status;
	ssize_t n, extra;

	extra = 1 + ((nochdir) ? 0 : sizeof("cd /; "));
	p = buf;
	va_start(ap, fmt);
	n = yvasnprintf(&p, sizeof(buf) - extra, fmt, ap);
	va_end(ap);

	if (p != buf)
		p = realloc(p, n + extra);

	if (!nochdir)
		strpull(p, n, "cd /; ", sizeof("cd /; ") - 1);

	argv[2] = strcat(p, "&");
	status = yexecv(argv, (noclose) ? NULL : ">/dev/null 2>&1", 0, NULL);
	if (p != buf)
		free(p);
	return status;
}
