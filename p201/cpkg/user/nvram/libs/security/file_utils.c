#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "file_utils.h"

#define DBG_PRINT(...)

__hidden int z_safe_read(int fd, void *buf, int count)
{
	ssize_t n;

	do {
		n = read(fd, buf, count);
	} while (n < 0 && errno == EINTR);
	return n;
}

__hidden int z_safe_write(int fd, void *buf, int count)
{
	ssize_t n;

	do {
		n = write(fd, buf, count);
	} while (n < 0 && errno == EINTR);
	return n;
}

__hidden int z_file_read(char *fname, unsigned char *buf, int buf_sz)
{
	int fd, ret;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return -1;
	ret = z_safe_read(fd, buf, buf_sz);
	close(fd);
	return ret;
}

__hidden int z_file_write(char *fname, unsigned char *buf, int buf_sz)
{
	int fd;
	int ret = 0;

	fd = open(fname, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (!fd)
		return -1;
	if (buf_sz > 0)
		ret = z_safe_write(fd, buf, buf_sz);
	fsync(fd);
	close(fd);
	return ret;
}

__hidden int z_file_compare(char *fname1, char *fname2)
{
	int fd1 = -1, fd2 = -1;
	int ret = -1;
	int len1, len2;
	unsigned char buf1[256];
	unsigned char buf2[256];

	fd1 = open(fname1, O_RDONLY);
	fd2 = open(fname2, O_RDONLY);
	if ((fd1 < 0) || (fd2 < 0)) {
		ret = -1;
		goto end;
	}

	len1 = lseek(fd1, 0, SEEK_END);
	len2 = lseek(fd2, 0, SEEK_END);
	if (len1 != len2) {	// file size mismatch
		ret = -2;
		goto end;
	}
	lseek(fd1, 0, SEEK_SET);
	lseek(fd2, 0, SEEK_SET);

	do {
		len1 = z_safe_read(fd1, buf1, sizeof(buf1));
		if (len1 > 0) {
			len2 = z_safe_read(fd2, buf2, len1);
			if (len1 != len2) {
				ret = -3;
				goto end;
			}
			if (memcmp(buf1, buf2, len1) != 0) {
				ret = -4;
				goto end;
			}
		}
	} while (len1 > 0);
	ret = 0;

 end:
	if (fd1 >= 0)
		close(fd1);
	if (fd2 >= 0)
		close(fd2);

	if (ret == 0)
		DBG_PRINT("%s %s same\n", fname1, fname2);
	else
		DBG_PRINT("%s %s different %d\n", fname1, fname2, ret);

	return ret;
}

__hidden int z_file_copy(char *src, char *dst)
{
	int fd1 = -1, fd2 = -1;
	int ret = -1;
	int len1;
	unsigned char buf1[256];
	int n = 0;

	fd1 = open(src, O_RDONLY);
	fd2 = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0600);

	if ((fd1 < 0) || (fd2 < 0)) {
		ret = -1;
		goto end;
	}

	do {
		len1 = z_safe_read(fd1, buf1, sizeof(buf1));
		if (len1 > 0) {
			z_safe_write(fd2, buf1, len1);
			n += len1;
		}
	} while (len1 > 0);
	ret = n;

	DBG_PRINT("%s -> %s copy\n", src, dst);
 end:
	if (fd1 >= 0)
		close(fd1);
	if (fd2 >= 0) {
		fsync(fd2);
		close(fd2);
	}
	return ret;
}

static int __z_file_cmp_copy(char *fname1, char *fname2, int op)
{
	if (op == Z_FILE_OP_CMP_COPY && !z_file_compare(fname1, fname2))
		return 0;
	// copy routine
	return z_file_copy(fname1, fname2);	// fname1 -> fname2
}

__hidden int z_file_cmp_copy(char *fname1, char *fname2, int op, int exec_op)
{
	int pid, sts;

	if (exec_op == Z_FILE_EXEC_OP_BG) {
		if (!(pid = fork())) {
			daemon(1, 1);	// do bg
			usleep(200 * 1000);
			__z_file_cmp_copy(fname1, fname2, op);
			exit(EXIT_SUCCESS);
		} else if (pid > 0) {
			waitpid(pid, &sts, 0);
			return 0;
		} // else // bg failed, do fg
	}

	return __z_file_cmp_copy(fname1, fname2, op);
}

__hidden int z_file_touch(char *fname)
{
	return z_file_write(fname, NULL, 0);
}
