#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <furl.h>
#include "dvbox.h"

#define in_range(c, lo, up)  ((int)(c) >= lo && (int)(c) <= up)
#define isdigit(c) in_range(c, '0', '9')
#define isupper(c) in_range(c, 'A', 'Z')
#define islower(c) in_range(c, 'a', 'z')
#define isalnum(c) (isdigit(c) || isupper(c) || islower(c))

static int validate_bootversion(u_int32_t ver)
{
	int i, c;

	if ((ver >> 24) != 'V')
		return -1;
	for (i = 0; i < 3; i++) {
		c = (ver >> (i << 3)) & 0xff;
		if (!isalnum(c))
			return -1;
	}
	return 0;
}

static int getbootversion(const char *path, u_int32_t offset, u_int32_t *ver)
{
	int fd = open(path, O_RDONLY);
	int n = 0;

	if (fd < 0)
		return -1;
	if (offset == (u_int32_t)lseek(fd, (off_t)offset, SEEK_SET))
		n = read(fd, ver, sizeof(u_int32_t));
	close(fd);
	return (n == sizeof(u_int32_t)) ? 0 : -1;
}

static int ub_main(int argc, char **argv)
{
	struct stat sb;
	u_int32_t curr, newer;
	struct fwstat fbuf;
	int fd, opt, status = -1, force = 0;

	while ((opt = getopt(argc, argv, "f")) != -1) {
		switch (opt) {
		case 'f':
			force = 1;
			break;
		default:
			exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc)
		exit(EXIT_FAILURE);

	if (argc < 2 || lstat(argv[optind], &sb) || sb.st_size < USHRT_MAX)
		exit(EXIT_FAILURE);

	if (getbootversion("/dev/mtd0", 12, &curr))
		exit(EXIT_FAILURE);

	if (getbootversion(argv[optind], 0x1c, &newer) || validate_bootversion(newer))
		exit(EXIT_FAILURE);

	if (!force && (!validate_bootversion(curr) && curr >= newer))
		exit(EXIT_FAILURE);

	fprintf(stderr, "replacing %c.%c.%c with %c.%c.%c bootrom\n",
		(curr >> 16) & 0xff, (curr >> 8) & 0xff, curr & 0xff,
		(newer >> 16) & 0xff, (newer >> 8) & 0xff, newer & 0xff);

	memset(&fbuf, 0, sizeof(fbuf));
	fd = open(argv[optind], O_RDONLY);
	if (fd < 0)
		exit(EXIT_FAILURE);

	fbuf.fmem = (char *)malloc(sb.st_size);
	fbuf.caplen = fbuf.rcvlen = sb.st_size;
	if (fbuf.fmem == NULL) {
		perror("upboot");
		goto abort;
	}
	if (sb.st_size != read(fd, fbuf.fmem, sb.st_size)) {
		perror("lacking count");
		goto abort;
	}

	status = fw_validate(&fbuf);
	if (!status) {
		status = fw_write_back(&fbuf, NULL, NULL, NULL, NULL);
		if (!status)
			fprintf(stdout, "Upgrading boot done\n");
	}
abort:
	if (fbuf.fmem)
		free(fbuf.fmem);
	close(fd);

	return status;
}
REG_APL_LEAF(ub);
