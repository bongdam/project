#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

int yvasnprintf(char **strp, size_t buflen, const char *fmt, va_list ap)
{
	va_list args;
	char *p;
	int n;

	if (strp == NULL || !(p = *strp))
		return 0;

	va_copy(args, ap);
	n = vsnprintf(p, buflen, fmt, args);
	va_end(args);
	if (n >= (int)buflen) {
		if ((p = (char *)malloc(n + 1))) {
			*strp = p;
			return vsnprintf(p, n + 1, fmt, ap);
		} else if (buflen)
			return buflen - 1;
	}
	return n;
}

char *yvasprintf(char *buf, size_t buflen, const char *fmt, va_list ap)
{
	char *p = buf;
	yvasnprintf(&p, buflen, fmt, ap);
	return p;
}

int yasnprintf(char **strp, size_t buflen, const char *fmt, ...)
{
	va_list args;
	int n;

	va_start(args, fmt);
	n = yvasnprintf(strp, buflen, fmt, args);
	va_end(args);
	return n;
}
