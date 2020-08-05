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

static void gpio_usage(char *prog)
{
	fprintf(stderr, "Usage: %s <-s out|in> <-w 0|1> <-r> 'gpio name'\n", prog);
	exit(EXIT_FAILURE);
}

static int gpio_main(int argc, char **argv)
{
	int fd, opt, cmd = -1;
	char name[4];

	while ((opt = getopt(argc, argv, "s:w:r")) != -1) {
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
			if (!strcasecmp(optarg, "1"))
				cmd = GPIOSHOUT;
			else if (!strcasecmp(optarg, "0"))
				cmd = GPIOSLOUT;
			else
				gpio_usage(argv[0]);
			break;
		case 'r':
			cmd = GPIOGIN;
			break;
		default:
			gpio_usage(argv[0]);
			break;
		}
	}
	if (optind >= argc)
		gpio_usage(argv[0]);
	snprintf(name, sizeof(name), "%s", argv[optind]);
	fd = open("/proc/brdio", O_RDWR);
	if (fd != -1) {
		if (ioctl(fd, cmd, (void *)name))
			perror(name);
		else if (cmd == GPIOGIN)
			printf("%d\n", *(int *)name);
		close(fd);
	} else
		perror("open");
	return 0;
}
REG_APL_LEAF(gpio);
