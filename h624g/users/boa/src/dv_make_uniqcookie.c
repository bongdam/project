#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "dv_make_uniqcookie.h"
#include "boa.h"
#include "utility.h"

#define PATH_CIPHERKEY  "/var/.w3cipherkey"

static int cipher_key;

//extern int increase_entropy(void);
//extern unsigned int seeding(void);

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

