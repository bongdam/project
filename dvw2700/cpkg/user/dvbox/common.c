#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

void error_msg_and_die(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

int safe_strtoul(const char *nptr, unsigned int *ulptr, int base)
{
	char *endptr;
	unsigned int tmp;
	int saved_errno = errno;

	if (!nptr || !nptr[0])
		return -1;
	errno = 0;
	tmp = strtoul(nptr, &endptr, base);
	if (errno)
		return -1;

	if (!endptr || *endptr) {
		errno = EINVAL;
		return -1;
	}

	errno = saved_errno;
	*ulptr = tmp;
	return 0;
}

ssize_t safe_read(int fd, void *buf, size_t count)
{
	ssize_t n;
	do {
		n = read(fd, buf, count);
	} while (n < 0 && errno == EINTR);
	return n;
}
