#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "libytool.h"

int yfecho(const char *pathname, int flags, mode_t mode, const char *fmt, ...)
{
	char *p, buffer[128];
	va_list args;
	int fd, n = -1;

	if (ystrlen_zero(pathname) || fmt == NULL)
		return -1;

	fd = open(pathname, flags, mode);
	if (fd < 0) {
		perror(pathname);
		return -1;
	}

	va_start(args, fmt);
	p = yvasprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);

	if (p != NULL) {
		n = write(fd, p, strlen(p));
		if (p != buffer)
			free(p);
	}

	close(fd);

	return n;
}
