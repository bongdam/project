#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <asm/byteorder.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include "dvbox.h"

struct mareqn {
	unsigned long addr;
	unsigned int len;
	char buf[0];
};

static void *mem_read_align(void *dst, const void *src, size_t n)
{
	char *d = (char *)dst;
	u_int32_t val;
	const u_int32_t *p = (u_int32_t *)(((long)src) & ~3);
	size_t i;

	if ((i = (((long)src) & 3))) {
		for (val = *p++; n > 0 && i < 4; n--)
			*d++ = ((char *)&val)[i++];
	}

	for (; n >= 4; n -= 4) {
		val = *p++;
		*d++ = ((char *)&val)[0];
		*d++ = ((char *)&val)[1];
		*d++ = ((char *)&val)[2];
		*d++ = ((char *)&val)[3];
	}

	if (n > 0) {
		val = *p++;
		for (i = 0; n > 0 && i < 4; n--)
			*d++ = ((char *)&val)[i++];
	}
	return dst;
}

static void *mem_write_align(void *dst, const void *src, size_t n)
{
	const char *p = (char *)src;
	u_int32_t val;
	u_int32_t *d = (u_int32_t *)(((long)dst) & ~3);
	size_t i;

	if ((i = (((u_int32_t)dst) & 3)) && n > 0) {
		for (val = *d; n > 0 && i < 4; n--)
			((char *)&val)[i++] = *p++;
		*d++ = val;
	}

	for (; n >= 4; n -= 4) {
		((char *)&val)[0] = *p++;
		((char *)&val)[1] = *p++;
		((char *)&val)[2] = *p++;
		((char *)&val)[3] = *p++;
		*d++ = val;
	}

	if (n > 0) {
		val = *d;
		for (i = 0; n > 0 && i < 4; n--)
			((char *)&val)[i++] = *p++;
		*d++ = val;
	}

	return dst;
}

static void mio_usage(int op)
{
	if (op == 0)
		fprintf(stderr, "Usage: md <address> <length>\n");
	else
		fprintf(stderr, "Usage: mm -bhw <address> <value>\n");
	exit(EXIT_SUCCESS);
}

static void mdisp(unsigned char *p, unsigned int s, unsigned long base)
{
	int i, c;

	while ((int)s > 0) {
		printf("%08lx: ", base);

		for (i = 0; i < 16; i++) {
			if (i < (int)s)
				printf("%02x ", p[i] & 0xFF);
			else
				printf("   ");

			if (i == 7)
				printf(" ");
		}
		printf(" |");
		for (i = 0; i < 16; i++) {
			if (i < (int)s) {
				c = p[i] & 0xFF;
				if ((c < 0x20) || (c >= 0x7F))
					c = '.';
			} else
				c = ' ';

			printf("%c", c);
		}
		printf("|\n");
		s -= 16;
		p += 16;
		base += 16;
	}
}

static struct mareqn *mkcmd(char *paddr, char *plen, char *pval)
{
	struct mareqn *req;
	unsigned long addr;
	unsigned int len;
	unsigned int val;

	if (safe_strtoul(paddr, &addr, 16) ||
	    safe_atoi(plen, &len, 0) ||
	    (pval && safe_atoi(pval, &val, 0)))
		return NULL;

	if (len > 0x1000)
		len = 0x1000;

	req = (struct mareqn *)malloc(sizeof(*req) + ((len + 3) & ~3));
	if (req) {
		req->addr = addr;
		req->len = len;
		if (pval)
#if defined(__LITTLE_ENDIAN_BITFIELD)
			memcpy(&req->buf, &val, len);
#elif defined (__BIG_ENDIAN_BITFIELD)
			memcpy(&req->buf, &((char *)&val)[4 - len], len);
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	}

	return req;
}

static int md_main(int argc, char **argv)
{
	struct mareqn *req;
	int fd;
	unsigned long mask, maplen;
	unsigned long offset, pos;
	char *mptr;

	if (argc != 3)
		mio_usage(0);

	req = mkcmd(argv[1], argv[2], NULL);
	if (!req)
		error_msg_and_die("mkcmd: %m\n");

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd == -1)
		error_msg_and_die("/dev/mem: %m\n");

	mask = (unsigned)getpagesize() - 1;
	offset = req->addr & ~mask;
	pos = req->addr - offset;
	maplen = ((req->len + pos) + mask) & ~mask;
	mptr = (char *)mmap(0, maplen, PROT_READ, MAP_SHARED, fd, offset);
	if ((void *)mptr != MAP_FAILED) {
		mem_read_align(req->buf, &mptr[pos], req->len);
		munmap((void *)mptr, maplen);
		mdisp((unsigned char *)req->buf, req->len, req->addr);
	}

	close(fd);
	free(req);
	if ((void *)mptr == MAP_FAILED)
		error_msg_and_die("mmap: %m\n");
	return 0;
}
REG_APL_LEAF(md);

static int mm_main(int argc, char **argv)
{
	struct mareqn *req;
	int fd, len = 0;
	unsigned long mask, maplen;
	unsigned long offset, pos;
	char *mptr;
	char *thisarg;
	char tmp[16];

	argc--;
	argv++;
	/* Parse any options */
	while (argc >= 1 && **argv == '-') {
		thisarg = *argv;
		thisarg++;

		switch (*thisarg) {
		case 'b':
			len = 1;
			break;
		case 'h':
			len = 2;
			break;
		case 'w':
			len = 4;
			break;
		default:
			mio_usage(1);
			break;
		}
		argc--;
		argv++;
	}

	if (len == 0 || argc != 2)
		mio_usage(1);

	sprintf(tmp, "%d", len);
	req = mkcmd(argv[0], tmp, argv[1]);
	if (!req)
		error_msg_and_die("mkcmd: %m\n");

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd == -1)
		error_msg_and_die("/dev/mem: %m\n");

	mask = (unsigned)getpagesize() - 1;
	offset = req->addr & ~mask;
	pos = req->addr - offset;
	maplen = ((req->len + pos) + mask) & ~mask;
	mptr = (char *)mmap(0, maplen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
	if ((void *)mptr != MAP_FAILED) {
		mem_write_align(&mptr[pos], req->buf, req->len);
		munmap((void *)mptr, maplen);
	}
	close(fd);
	free(req);
	if ((void *)mptr == MAP_FAILED)
		error_msg_and_die("mmap: %m\n");
	return 0;
}
REG_APL_LEAF(mm);
