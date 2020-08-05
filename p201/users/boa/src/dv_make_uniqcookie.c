#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <libytool.h>
#include "dv_make_uniqcookie.h"
#include "boa.h"

/*
* base64 encoder
*
* encode 3 8-bit binary bytes as 4 '6-bit' characters
*/
char *b64_encode(unsigned char *src, int src_len, unsigned char *space, int space_len)
{
	static const char cb64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	unsigned char *out = space;
	unsigned char *in = src;
	int sub_len, len;
	int out_len;

	out_len = 0;

	if (src_len < 1)
		return NULL;
	if (!src)
		return NULL;
	if (!space)
		return NULL;
	if (space_len < 1)
		return NULL;

	/* Required space is 4/3 source length  plus one for NULL terminator */
	if (space_len < ((1 + src_len / 3) * 4 + 1))
		return NULL;

	memset(space, 0, space_len);

	for (len = 0; len < src_len; in = in + 3, len = len + 3) {

		sub_len = ((len + 3 < src_len) ? 3 : src_len - len);

		/* This is a little inefficient on space but covers ALL the
		   corner cases as far as length goes */
		switch (sub_len) {
		case 3:
			out[out_len++] = cb64[in[0] >> 2];
			out[out_len++] = cb64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
			out[out_len++] = cb64[((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)];
			out[out_len++] = cb64[in[2] & 0x3f];
			break;
		case 2:
			out[out_len++] = cb64[in[0] >> 2];
			out[out_len++] = cb64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
			out[out_len++] = cb64[((in[1] & 0x0f) << 2)];
			out[out_len++] = (unsigned char)'=';
			break;
		case 1:
			out[out_len++] = cb64[in[0] >> 2];
			out[out_len++] = cb64[((in[0] & 0x03) << 4)];
			out[out_len++] = (unsigned char)'=';
			out[out_len++] = (unsigned char)'=';
			break;
		default:
			break;
			/* do nothing */
		}
	}
	out[out_len] = '\0';
	return (char *)out;
}

/* Base-64 decoding.  This represents binary data as printable ASCII
** characters.  Three 8-bit binary bytes are turned into four 6-bit
** values, like so:
**
**   [11111111]  [22222222]  [33333333]
**
**   [111111] [112222] [222233] [333333]
**
** Then the 6-bit values are represented using the characters "A-Za-z0-9+/".
*/

static const char b64_decode_table[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* 00-0F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* 10-1F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,	/* 20-2F */
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,	/* 30-3F */
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,	/* 40-4F */
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,	/* 50-5F */
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,	/* 60-6F */
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,	/* 70-7F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* 80-8F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* 90-9F */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* A0-AF */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* B0-BF */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* C0-CF */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* D0-DF */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,	/* E0-EF */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1	/* F0-FF */
};

/* Do base-64 decoding on a string.  Ignore any non-base64 bytes.
** Return the actual number of bytes generated.  The decoded size will
** be at most 3/4 the size of the encoded, and may be smaller if there
** are padding characters (blanks, newlines).
*/
int b64_decode(const char *str, unsigned char *space, int size)
{
	const unsigned char *cp;
	int space_idx, phase;
	int d, prev_d = 0;
	unsigned char c;

	space_idx = 0;
	phase = 0;
	for (cp = (unsigned char *)str; *cp != '\0'; ++cp) {
		d = b64_decode_table[*cp];
		if (d != -1) {
			switch (phase) {
			case 0:
				++phase;
				break;
			case 1:
				c = ((prev_d << 2) | ((d & 0x30) >> 4));
				if (space_idx < size)
					space[space_idx++] = c;
				++phase;
				break;
			case 2:
				c = (((prev_d & 0xf) << 4) | ((d & 0x3c) >> 2));
				if (space_idx < size)
					space[space_idx++] = c;
				++phase;
				break;
			case 3:
				c = (((prev_d & 0x03) << 6) | d);
				if (space_idx < size)
					space[space_idx++] = c;
				phase = 0;
				break;
			}
			prev_d = d;
		}
	}
	return space_idx;
}

#define PATH_CIPHERKEY  "/var/.w3cipherkey"

static int cipher_key;

int increase_entropy(void)
{
	FILE *f;
	int fd;
	unsigned int val;

	fd = open("/dev/urandom", O_WRONLY);
	if (fd < 0) {
		return 0;
	}

	f = fopen("/proc/interrupts", "r");
	if (!f) {
		close(fd);
		return 0;
	}

	fscanf(f, "%*[^\n]");
	while (fscanf(f, "%*s%u%*[^\n]", &val) > 0) {
		if (val > 0)
			write(fd, &val, sizeof(val));
	}

	fclose(f);
	close(fd);
	return 1;
}

unsigned int seeding(void)
{
#define ENTROPY_LEN 1024
	int i, fd;
	unsigned char dat[ENTROPY_LEN];
	unsigned int seed;
	struct timeval tv;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd != -1) {
		do {
			read(fd, dat, ENTROPY_LEN);
			for (i = 0; i < ENTROPY_LEN; i++)
				seed ^= ((int)dat[i] << (i & 0x1F));
		} while (!seed);
		close(fd);
	} else {
		gettimeofday(&tv, NULL);
		srand((tv.tv_sec * 1000) + (tv.tv_usec / 1000));
		while (!(seed = rand())) ;
	}

	return seed;
#undef ENTROPY_LEN
}

int rand_cipherkey(void)
{
	FILE *f;
	int ckey;

	f = fopen(PATH_CIPHERKEY, "rb");
	if (f) {
		int n = fread(&ckey, 1, sizeof(ckey), f);
		fclose(f);
		if (n == sizeof(ckey) && ckey != 0)
			return ckey;
	}

	increase_entropy();
	ckey = (int)seeding();

	f = fopen(PATH_CIPHERKEY, "wb");
	if (f) {
		fwrite(&ckey, 1, sizeof(ckey), f);
		fclose(f);
	} else
		perror(PATH_CIPHERKEY);

	return ckey;
}

static void simple_crypt(char *p, int len, int key)
{
	int i;
	char *pch = (char *)&key;

	for (i = 1; i < len; i++)
		p[i] += p[i - 1];

	for (i = 0; i < len; i++)
		p[i] ^= pch[i & 3];
}

static void simple_decrypt(char *p, int len, int key)
{
	int i;
	char *pch = (char *)&key;

	for (i = 0; i < len; i++)
		p[i] ^= pch[i & 3];

	for (i = len - 1; i > 0; i--)
		p[i] -= p[i - 1];
}

static inline unsigned rotatel(unsigned l)
{
	int i;
	unsigned t = 0;
	for (i = 0; i < 32; i++) {
		if ((l & (1 << i)))
			t |= (1 << (32 - i));
	}
	return t;
}

// {access-time}-{userid[:passwd]}
char *creat_cookie(const char *uid, const char *pwd, struct in_addr host, char *out, size_t outlen)
{
	char buf[256];
	int len;

	if (!cipher_key)
		cipher_key = rand_cipherkey();
	len = snprintf(buf, sizeof(buf) - 3, "%08x-%s%s%s-%s",
		       rotatel((unsigned)time(NULL)),
		       uid, pwd ? ":" : "", pwd ? pwd : "", inet_ntoa(host));
	while ((len % 3))
		buf[len++] = ' ';
	buf[len] = '\0';
	simple_crypt(buf, len, cipher_key);
	return b64_encode((unsigned char *)buf, len, (unsigned char *)out,
			  outlen);
}

int parse_line(char *line, char *argv[], int argvLen, const char *delim)
{
	char *q, *p = line;
	int i, argc = 0;

	while ((q = strsep(&p, delim))) {
		ydespaces(q);
		if (*q && (argc < argvLen))
			argv[argc++] = q;
	}
	for (i = argc; i < argvLen; i++)
		argv[i] = NULL;
	return argc;
}

int parse_cookie(const char *cookie, struct cookie_session *cs)
{
	size_t length = strlen(cookie);
	char *p, *q;
	int res = -1;
	char *tokens[8];

	if (!cipher_key)
		return -1;

	memset(cs, 0, sizeof(*cs));
	p = (char *)malloc(length + 1);
	if (!p)
		return -1;

	length = b64_decode(cookie, (unsigned char *)p, length);

	p[length] = '\0';
	simple_decrypt(p, length, cipher_key);
	if (parse_line(p, tokens, 8, "-\r\n") == 3) {
		cs->jiffy = rotatel((unsigned)strtoul(tokens[0], NULL, 16));
		cs->host.s_addr = inet_addr(tokens[2]);
		q = strchr(tokens[1], ':');
		if (q) {
			*q++ = '\0';
			strncpy(cs->pwd, q, MAX_UIDLEN - 1);
		}
		strncpy(cs->uid, tokens[1], MAX_UIDLEN - 1);
		res = 0;
	}
	free(p);
	return res;
}

