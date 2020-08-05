#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <bcmnvram.h>
#include <libytool.h>
#include "dvbox.h"

static char *rand_string(char *dst, size_t len)
{
	const char seedchars[] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	int fd, i;
	struct timeval tv;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd > -1) {
		TEMP_FAILURE_RETRY(read(fd, dst, len));
		close(fd);
	} else {
		gettimeofday(&tv, NULL);
		srand(tv.tv_sec * 1000000 + tv.tv_usec);
		for (i = 0; i < len; i++)
			dst[i] = rand() & 0xff;
	}

	for (i = 0; i < len; i++)
		dst[i] = seedchars[dst[i] % (sizeof(seedchars) - 1)];
	dst[i] = '\0';
	return dst;
}

static int chpwd_main(int argc, char **argv) __attribute__ ((__noreturn__));
static int chpwd_main(int argc, char **argv)
{
	char buf[80];
	int status, opt, force = 0;

	while ((opt = getopt(argc, argv, "f")) != -1) {
		switch (opt) {
		case 'f':
			force = 1;
			break;
		default:
			exit(1);
			break;
		}
	}

	if ((argc - optind) < 2)
		exit(1);

	if (nvram_aes_cbc_get(argv[optind + 1], buf, sizeof(buf))) {
		if (!force)
			exit(1);
		rand_string(buf, 8);
	}

	status = yexecl(">/dev/null 2>&1",
			"sh -c \"echo -e '%s\n%s' | passwd -a sha256 %s\"",
			buf, buf, argv[optind]);
	exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
}
REG_APL_LEAF(chpwd);
