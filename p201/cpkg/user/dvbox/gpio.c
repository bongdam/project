#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <brdio.h>
#include "dvbox.h"

static inline void gpio_usage(char *prog)
{
	error_msg_and_die("Usage: %s <-s out|in> <-w 0|1> <-r> <-S value> 'gpio name'", prog);
}

static int gpio_main(int argc, char **argv)
{
	int fd, opt, cmd = -1;
	union {
		unsigned int value[2];
		char name[sizeof(int) << 1];
	} u;

	while ((opt = getopt(argc, argv, "s:w:rS:")) != -1) {
		switch (opt) {
		case 's':
			if (!strcasecmp(optarg, "out"))
				cmd = GPIOCOUT;
			else if (!strcasecmp(optarg, "in"))
				cmd = GPIOCIN;
			else
				gpio_usage(argv[0]);
			break;
		case 'w':
			if (safe_atoi(optarg, &u.value[1], 0))
				gpio_usage(argv[0]);
			else if (cmd < 0)
				cmd = u.value[1] ? GPIOSHOUT : GPIOSLOUT;
			break;
		case 'r':
			cmd = GPIOGIN;
			break;
		case 'S':
			cmd = GPIODECFG;
			u.value[1] = (int)strtoul(optarg, NULL, 0);
			break;
		default:
			gpio_usage(argv[0]);
			break;
		}
	}
	if (optind >= argc)
		gpio_usage(argv[0]);
	snprintf(u.name, sizeof(u.value[0]), "%s", argv[optind]);
	fd = open("/proc/brdio", O_RDWR);
	if (fd != -1) {
		if (ioctl(fd, cmd, (void *)&u))
			error_msg_and_die("%s: %m", u.name);
		else if (cmd == GPIOGIN)
			printf("%u\n", u.value[0]);
		close(fd);
	} else
		error_msg_and_die("open: %m");
	return 0;
}
REG_APL_LEAF(gpio);
