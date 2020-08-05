#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/syscall.h>
#include <dvflag.h>
#include "dvbox.h"

#define monotonic_ms()							\
({									\
	struct timespec __ts;						\
	long __ms;							\
	syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &__ts);		\
	__ms = (long)(__ts.tv_sec * 1000UL + __ts.tv_nsec / 1000000);	\
	__ms;								\
})

static int test_all_flag_set(unsigned int mask, unsigned int old, unsigned int new)
{
	return test_all_bits(mask, new);
}

static int test_any_flag_set(unsigned int mask, unsigned int old, unsigned int new)
{
	return test_any_bit(mask, new);
}

static int test_invert_flag_set(unsigned int mask, unsigned int old, unsigned int new)
{
	return test_inverted_set(mask, old, new);
}

static int test_invert_flag_clr(unsigned int mask, unsigned int old, unsigned int new)
{
	return test_inverted_clear(mask, old, new);
}

static int __attribute__ ((__noreturn__)) xpoll_flag(unsigned int mask,
	int timeout, int (*tst)(unsigned int, unsigned int, unsigned int))
{
	struct pollfd pfd;
	unsigned int flag, old;
	int expiry;

	pfd.fd = open("/proc/dvflag", O_RDWR);
	if (pfd.fd < 0)
		exit(EXIT_FAILURE);
	read(pfd.fd, (void *)&flag, sizeof(flag));
	if (tst(mask, ~flag, flag))
		exit(EXIT_SUCCESS);
	old = flag;
	pfd.events = POLLIN;
	if (timeout > 0)
		expiry = (int)monotonic_ms() + timeout;

	for (;;) {
		if (TEMP_FAILURE_RETRY(poll(&pfd, 1, timeout)) <= 0)
			exit(EXIT_FAILURE);
		else {
			read(pfd.fd, (void *)&flag, sizeof(flag));
			if (tst(mask, old, flag))
				break;
			old = flag;
		}
		if (timeout > 0) {
			timeout = expiry - (int)monotonic_ms();
			if (timeout <= 0)
				exit(EXIT_FAILURE);
		}
	}
	close(pfd.fd);
	exit(EXIT_SUCCESS);
}

static int flagcompr(const char *name, unsigned flg, const char *input)
{
	return strcasecmp(name, input);
}

static unsigned flagnam(int (*iterator)(const char *, unsigned, void *), void *data)
{
	static const struct {
		unsigned flg;
		const char *name;
	} maps[] = {
		{ DF_WANLINK, "WANLINK" },
		{ DF_LANLINK1, "LANLINK1" },
		{ DF_LANLINK2, "LANLINK2" },
		{ DF_LANLINK3, "LANLINK3" },
		{ DF_LANLINK4, "LANLINK4" },
		{ DF_WANBOUND, "WANBOUND" },
		{ DF_LANBOUND, "LANBOUND" },
		{ DF_IPADDRDUP, "IPADDRDUP" },
		{ DF_UPLOADING, "UPLOADING" },
		{ DF_NTPSYNC, "NTPSYNC" },
		{ DF_INITED, "INITED" },
		{ DF_REBOOTING, "REBOOTING" },
		{ DF_RSTASSERTED, "RSTASSERTED" },
		{ DF_WPSASSERTED, "WPSASSERTED" },
		{ DF_WANIPFILE, "WANIPFILE" },
		{ 0, NULL} };
	int i;

	for (i = 0; maps[i].name; i++)
		if (!iterator(maps[i].name, maps[i].flg, data))
			return maps[i].flg;
	return 0;
}

static int flagprint(const char *name, unsigned flg, unsigned input)
{
	return printf("%s=%d\n", name, !!(flg & input));
}

static int dvflag_main(int argc, char *argv[]) __attribute__ ((__noreturn__));
static int dvflag_main(int argc, char *argv[])
{
	int fd, verbose = 1, opt;
	unsigned int flag, val[2];
	useconds_t linger = 0;

	while ((opt = getopt(argc, argv, "s:")) != -1) {
		switch (opt) {
		case 's':
			linger = strtoul(optarg, NULL, 0);
		default:
			break;
		}
	}

	fd = open("/proc/dvflag", O_RDWR);
	if (fd != -1) {
		if ((optind + 1) < argc) {
			val[1] = flagnam((void *)flagcompr, argv[optind]);
			if (val[1]) {
				val[0] = (atoi(argv[optind + 1])) ? val[1] : 0;
				write(fd, val, sizeof(val));
				verbose = 0;
			}
		}
		read(fd, (void *)&flag, sizeof(int));
		close(fd);
		if (verbose)
			flagnam((void *)flagprint, (void *)flag);
		else if (linger > 0)
			xpoll_flag(val[1], linger * 1000,
				(val[0] & val[1]) ? test_invert_flag_clr : test_invert_flag_set);
		exit(EXIT_SUCCESS);
	}
	exit(EXIT_FAILURE);
}
REG_APL_LEAF(dvflag);

static int waitflag_main(int argc, char *argv[]) __attribute__ ((__noreturn__));
static int waitflag_main(int argc, char *argv[])
{
	unsigned int mask;
	char *p;

	if (argc < 4)
		exit(EXIT_FAILURE);

	mask = strtoul(argv[1], &p, 0);
	if (*p == '\0' && argv[1] == p)
		exit(EXIT_FAILURE);
	else if (*p != '\0')
		mask = flagnam((void *)flagcompr, argv[1]);

	if (mask)
		xpoll_flag(mask, strtoul(argv[3], NULL, 0),
			strtoul(argv[2], NULL, 0) ? test_all_flag_set : test_any_flag_set);
	exit(EXIT_FAILURE);
}
REG_APL_LEAF(waitflag);
