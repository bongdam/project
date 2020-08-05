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
#include <sys/mman.h>
#include <regex.h>
#include <libytool.h>
#include <furl.h>
#include "dvbox.h"

#define MAX_TRY     4
#define MAX_TIMEO   4000

static int test_url(const char *name)
{
	regex_t reg;
	regmatch_t match[4];
	int eret;

	if (name == NULL || !name[0])
		return -1;
	if (regcomp(&reg, "^[A-Za-z][A-Za-z0-9+\\-\\.]*://", REG_EXTENDED | REG_NEWLINE))
		return -1;
	eret = regexec(&reg, name, _countof(match), match, 0);
	regfree(&reg);
	return eret;
}

static int do_wget(struct fwstat *fbuf, int *exp, int timeo, const char *url)
{
	char cmd[256];
	int try;
	long begin, delay;

	snprintf(cmd, sizeof(cmd), "wget -q -O - \"%s\"", url);
	for (try = 0; try < MAX_TRY; try++) {
		begin = ygettime(NULL);
		/* put the 5 mins cap */
		delay = (*exp < 7) ? (3 * (1 << *exp)) : 300;
		delay += ((rand() % 3) + 1);
		++*exp;
		if (!furl(cmd, timeo, (p_read_f)fw_read_callback, (void *)fbuf))
			return (!fbuf->lasterror && fbuf->rcvlen > 0) ? 0 : -1;

		delay -= ((long)ygettime(NULL) - begin);
		if (delay > 0 && ((try + 1) < MAX_TRY))
			sleep(delay);
	}
	return -1;
}

static int file_to_buffer(const char *name, struct fwstat *fbuf)
{
	struct stat stat_buf;
	int fd, n, bufsiz, std_input;

	if ((std_input = !strcmp(name, "-")) || test_url(name)) {
		if (std_input)
			fd = STDIN_FILENO;
		else if (stat(name, &stat_buf))
			return -errno;
		else if (stat_buf.st_size > (off_t)fbuf->caplen)
			return -EFBIG;
		else if ((fd = open(name, O_RDONLY)) < 0)
			return -errno;

		while (fbuf->lasterror == 0) {
			bufsiz = fbuf->caplen - fbuf->rcvlen;
			if (bufsiz > 0)
				n = safe_read(fd, fbuf->fmem + fbuf->rcvlen, bufsiz);
			else
				n = safe_read(fd, &stat_buf, sizeof(stat_buf));
			if (n < 0)
				fbuf->lasterror = -errno;
			else if (n == 0)
				break;
			else if ((fbuf->rcvlen + n) > fbuf->caplen)
				fbuf->lasterror = -EFBIG;
			else
				fbuf->rcvlen += n;
		}

		if (std_input == 0)
			close(fd);
	} else {
		int exp = 0;
		if (do_wget(fbuf, &exp, MAX_TIMEO, name))
			return -EGETFW;
	}

	return (!fbuf->lasterror && fbuf->rcvlen > 0) ? 0 : -1;
}

static int furl_main(int argc, char **argv)
{
	struct fwstat fbuf;
	char *mm;
	int status, ch, restart = 0, foreground = 1;

	while ((ch = getopt(argc, argv, "rd")) != -1) {
		switch (ch) {
		case 'r':
			restart = 1;
			break;
		case 'd':
			foreground = 0;
			break;
		default:
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (argv[optind] == NULL)
		exit(EXIT_FAILURE);

	mm = mmap(NULL, MAX_FWSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (mm == MAP_FAILED) {
		perror("mmap");
		exit(errno & 0377);
	}

	memset(&fbuf, 0, sizeof(fbuf));
	fbuf.fmem = mm;
	fbuf.caplen = MAX_FWSIZE;

	status = file_to_buffer(argv[optind], &fbuf);
	if (status == 0) {
		fprintf(stderr, "Image length %d\n", fbuf.rcvlen);
		fw_parse_bootline(&fbuf.blnfo);
		status = fw_validate(&fbuf);
		if (!status && !(status = fw_dualize(&fbuf))) {
			if (!foreground)
				daemon(0, 1);
			status = fw_write(&fbuf, NULL, NULL);
			if (!status) {
				munmap(mm, MAX_FWSIZE);
				mm = MAP_FAILED;
				fprintf(stderr, "V%02u.%02d.%02d software has been upgraded successfully\n",
					(fbuf.version >> 14), (fbuf.version >> 7) & 0x7f, fbuf.version& 0x7f);
				if (restart)
					yexecl(NULL, "reboot");
				exit(EXIT_SUCCESS);
			}
		}
	}

	if (mm != MAP_FAILED)
		munmap(mm, MAX_FWSIZE);

	fprintf(stderr, "%s\n", fw_strerror(status));
	exit((0 - status) & 0377);
	return 0;
}
REG_APL_LEAF(furl);
