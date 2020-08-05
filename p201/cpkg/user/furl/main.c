#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <regex.h>
#include <limits.h>
#include <libytool.h>
#include "goods.h"
#include "furl.h"

#define in_range(c, lo, up)  ((int)(c) >= lo && (int)(c) <= up)
#define isdigit(c) in_range(c, '0', '9')
#define isupper(c) in_range(c, 'A', 'Z')
#define islower(c) in_range(c, 'a', 'z')
#define isalnum(c) (isdigit(c) || isupper(c) || islower(c))

#define MAX_TRY     4
#define MAX_TIMEO   4000

extern int fota_check(int argc, char **argv) __attribute__ ((__noreturn__));

static ssize_t safe_read(int fd, void *buf, size_t count)
{
	ssize_t n;
	do {
		n = read(fd, buf, count);
	} while (n < 0 && errno == EINTR);
	return n;
}

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

int do_wget(struct fwstat *fbuf, int *exp, int timeo, const char *url)
{
	char cmd[256];
	int try;
	long begin, delay;

#ifdef __CONFIG_LIB_CURL_NEW__
	snprintf(cmd, sizeof(cmd), "curl -fvs \"%s\"", url);
#else
	snprintf(cmd, sizeof(cmd), "wget -q -O - \"%s\"", url);
#endif
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

#ifdef __CONFIG_SEC_CONTAINER__
#include <libdvct.h>

static int ct_unroll(void *src, int *len)
{
	char tmp[] = "/tmp/XXXXXX";
	int fd, status = -1;
	ssize_t n;
	struct stat sb;

	if (!dvct_is_magic((struct dvcontainer_t *)src))
		return -1;
	fd = mkstemp(tmp);
	if (fd < 0)
		return -1;
	n = TEMP_FAILURE_RETRY(write(fd, src, *len));
	close(fd);
	if (n == (ssize_t)*len) {
		status = yexecl(NULL, "dvct_unroll %s 0x%x", tmp, GOODS_ID);
		status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		if (!status) {
			fd = open(tmp, O_RDONLY);
			if (fstat(fd, &sb))
				status = -1;
			else if (sb.st_size > (off_t)*len) {
				status = -1;
				errno = EFBIG;
			} else {
				n = TEMP_FAILURE_RETRY(read(fd, src, (size_t)sb.st_size));
				if (n == (size_t)sb.st_size)
					*len = (int)n;
				else
					status = -1;
			}
			close(fd);
		} else
			fprintf(stderr, "Failed to unroll with %d error", status);
	}
	unlink(tmp);
	return status;
}
#endif

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
#ifdef __CONFIG_SEC_CONTAINER__
		status = ct_unroll(fbuf.fmem, &fbuf.rcvlen);
		if (status)
			exit((0 - status) & 0377);
#endif
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
					(fbuf.version >> 14), (fbuf.version >> 7) & 0x7f, fbuf.version & 0x7f);
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

int main(int argc, char *argv[])
{
	char *base = basename(argv[0]);

	if (!strcmp(base, "ub"))
		return ub_main(argc, argv);
	else if (!strcmp(base, "fota_check"))
		return fota_check(argc, argv);
	else
		return furl_main(argc, argv);
}
