#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "aes.h"

static void die(const char *fmt, ...) __attribute__((noreturn));
static void die(const char *fmt, ...)
{
	va_list p;
	va_start(p, fmt);
	vfprintf(stderr, fmt, p);
	va_end(p);
	exit(EXIT_FAILURE);
}

static GIO *gio_xalloc(char *path, bool out)
{
	GIO *g;
	int fd = -1, noclose = GIO_NOCLOSE;

	if (path == NULL || !strcmp(path, "-"))
		fd = (out == true) ? STDOUT_FILENO : STDIN_FILENO;
	else if (path) {
		fd = open(path, (out == true) ?
			O_WRONLY | O_CREAT | O_TRUNC : O_RDONLY, 0644);
		noclose = GIO_CLOSE;
	}

	if (fd < 0)
		die("%s: %m\n", path);

	g = gio_new_fd(fd, noclose);
	if (g == NULL && ({ close(fd); 1; }))
		die("gio_new_fd: %m\n");

	return g;
}

static ssize_t aes_cbs_exec(char *in, char *out, uint8 *IV, uint8 *K, bool enc)
{
	GIO *gin = gio_xalloc(in, false);
	GIO *gout = gio_xalloc(out, true);
	ssize_t ret;

	if (enc == true)
		ret = GIO_aes_cbc_encrypt(gin, gout, IV, K);
	else
		ret = GIO_aes_cbc_decrypt(gin, gout, IV, K);

	gio_free(gin);
	gio_free(gout);
	return ret;
}

int main(int argc, char **argv)
{
	int opt, act = -1;
	char *in = NULL;
	char *out = NULL;
	uint8 K[AES_BLOCK_SZ] = { [0 ... (AES_BLOCK_SZ - 1)] = '0' };
	uint8 IV[AES_BLOCK_SZ];

	strncpy((char *)IV, "0123456789aBCdEf", sizeof(IV));

	while ((opt = getopt(argc, argv, ":dei:o:k:V:")) != -1) {
		switch (opt) {
		case 'e':
		case 'd':
			act = opt;
			break;
		case 'i':
			free(in);
			in = strdup(optarg);
			break;
		case 'o':
			free(out);
			out = strdup(optarg);
			break;
		case 'k':
			strncpy((char *)K, optarg, sizeof(K));
			break;
		case 'V':
			strncpy((char *)IV, optarg, sizeof(IV));
			break;
		default:
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (act < 0)
		exit(EXIT_FAILURE);

	aes_cbs_exec(in, out, IV, K, (act == 'e') ? true : false);

	free(in);
	free(out);

	exit(EXIT_SUCCESS);
}
