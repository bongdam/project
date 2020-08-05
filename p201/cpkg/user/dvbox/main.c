#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "dvbox.h"

extern struct applet_entry __start_applet_entries;
extern struct applet_entry __stop_applet_entries;

int main(int argc, char **argv)
{
	struct applet_entry *p;
	const char *applet_name = argv[0];

	if (applet_name[0] == '-')
		applet_name++;
	applet_name = basename(applet_name);

	for (p = &__start_applet_entries; p != &__stop_applet_entries; p++) {
		if (!strcmp(applet_name, p->name))
			return p->main(argc, argv);
	}
	fprintf(stderr, "Unknown applet name\n");
	exit(EXIT_FAILURE);
}

int safe_strtoul(const char *nptr, unsigned long *ulptr, int base)
{
	char *endptr;
	unsigned long tmp;
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

#if __BITS_PER_LONG > 32
int safe_atoi(const char *nptr, unsigned int *uptr, int base)
{
	unsigned long val;
	switch (safe_strtoul(nptr, &val, base)) {
	case 0:
		if (!(val >> 32L)) {
			*uptr = (unsigned int)val;
			return 0;
		}
		errno = ERANGE;
	default:
		return -1;
	}
}
#else
#define safe_atoi(nptr, uptr, base) safe_strtoul(nptr, (unsigned long *)uptr, base)
#endif

void error_msg_and_die(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}
