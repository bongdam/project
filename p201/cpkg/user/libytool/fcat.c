#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include "libytool.h"

int yfcat(const char *pathname, const char *fmt, ...)
{
	FILE *f;
	va_list args;

	if (ystrlen_zero(pathname) || ystrlen_zero(fmt))
		return 0;

	f = fopen(pathname, "r");
	if (f != NULL) {
		int n;

		va_start(args, fmt);
		n = vfscanf(f, fmt, args);
		va_end(args);
		fclose(f);
		return n;
	}

	return 0;
}
