#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bcmnvram.h>
#include <dvflag.h>

extern int nvram_load(const char *path, void *dst);

static char *strtrim(char *s, const char *exclude)
{
	const char *spanp;
	char *p, *q;
	char c, sc;

	if (!s || s[0] == 0)
		return s;

	/* skip leading spaces */
	for (p = s; (c = *p); p++) {
		spanp = (char *)exclude;
		do {
			if ((sc = *spanp++) == c)
				break;
		} while (sc != 0);
		if (sc == 0)
			break;
	}

	/* go to end of string */
	for (q = p; *q != 0; q++) ;
	/* truncate trailing spaces */
	while (p != q) {
		c = *(q - 1);
		spanp = (char *)exclude;
		do {
			if ((sc = *spanp++) == c) {
				*--q = 0;
				break;
			}
		} while (sc != 0);

		if (sc == 0)
			break;
	}

	if (p == s)
		return s;

	for (q = s; *p != 0; *s++ = *p++) ;
	*s = 0;
	return q;
}

static char *strpescape(char *string)
{
	char *cp, *sp = string;
	int squote = 0;
	int dquote = 0;
	int bsquote = 0;

	if (sp == NULL)
		return NULL;

	for (cp = sp ; *sp; sp++) {
		if (bsquote) {
			bsquote = 0;
			*cp++ = *sp;
		} else if (*sp == '\\') {
			bsquote = 1;
		} else if (squote) {
			if (*sp == '\'')
				squote = 0;
			else
				*cp++ = *sp;
		} else if (dquote) {
			if (*sp == '"')
				dquote = 0;
			else
				*cp++ = *sp;
		} else {
			if (*sp == '\'')
				squote = 1;
			else if (*sp == '"')
				dquote = 1;
			else
				*cp++ = *sp;
		}
	}
	*cp = '\0';
	return string;
}

static int _nvram_put(const char *fmt, va_list ap)
{
	char buf[128];
	va_list aq;
	char *name, *p = buf;
	int n;

	va_copy(aq, ap);
	n = vsnprintf(p, sizeof(buf), fmt, aq);
	va_end(aq);
	if (n >= (int)sizeof(buf) && (p = alloca(n + 1)))
		vsnprintf(p, n + 1, fmt, ap);

	/* If p is NULL, strsep() returns NULL */
	name = strsep(&p, "=");
	if (p)
		return nvram_set(name, strpescape(strtrim(p, " \f\n\r\t\v")));
	/* if name is NULL, nvram_unset returns -1 */
	return nvram_unset(name);
}

static int nvram_put(const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = _nvram_put(fmt, ap);
	va_end(ap);
	return rc;
}

static void __attribute__ ((__noreturn__)) usage(void)
{
	fprintf(stderr,
		"usage: nvram [get name] [set name=value] "
		"[unset name] [show] [commit] ...\n");
	exit(EXIT_FAILURE);
}

enum {
	CMD_GET,
	CMD_SET,
	CMD_UNSET,
	CMD_COMMIT,
	CMD_SHOW,
	CMD_POPULATE,
	CMD_FSET,
	CMD_PRINT,
};

enum {
	SHA_256 = 1,
	SHA_512,
	AES_128_CBC,
};

/* NVRAM utility */
int main(int argc, char **argv)
{
	char buf[MAX_NVRAM_SPACE];
	struct nvram_header *nh;
	char *name, *value;
	char *p;
	int cmd, rc = -1, opt, cipher = 0, c;

	while ((opt = getopt(argc, argv, "d:e")) != -1) {
                switch (opt) {
                case 'e':
                        cipher = AES_128_CBC;
                        break;
                case 'd':
                	if (!strcasecmp(optarg, "sha256"))
				cipher = SHA_256;
			else if (!strcasecmp(optarg, "sha512"))
				cipher = SHA_512;
			else
				exit(EXIT_FAILURE);
			break;
                default:
			exit(EXIT_FAILURE);
                }
        }

	if (optind >= argc)
		exit(EXIT_FAILURE);

	argc -= optind;
	argv = argv + optind;

	if (!*argv)
		usage();
	else if (!strcmp(*argv, "get"))
		cmd = CMD_GET;
	else if (!strcmp(*argv, "set")) {
		cmd = CMD_SET;
	} else if (!strcmp(*argv, "unset"))
		cmd = CMD_UNSET;
	else if (!strcmp(*argv, "commit"))
		cmd = CMD_COMMIT;
	else if (!strcmp(*argv, "show")) {
		cmd = CMD_SHOW;
	} else if (!strcmp(*argv, "populate"))
		cmd = CMD_POPULATE;
	else if (!strcmp(*argv, "fset"))
		cmd = CMD_FSET;
	else if (!strcmp(*argv, "print"))
		cmd = CMD_PRINT;
	else
		usage();

	--argc;
	++argv;

	switch (cmd) {
	case CMD_GET:
		if (argc > 0) {
#ifdef __EMUL__
			if (cipher == AES_128_CBC) {
				if (!nvram_aes_cbc_get(*argv, buf, sizeof(buf)))
					puts(buf);
			} else
#endif
			if ((value = nvram_get(*argv)))
				puts(value);
		}
		break;
	case CMD_SET:
		if (argc > 0) {
			snprintf(value = buf, sizeof(buf), "%s", *argv);
			name = strsep(&value, "=");
			switch (cipher) {
			case SHA_256:
				rc = nvram_sha_256_set(name, value);
				break;
			case SHA_512:
				rc = nvram_sha_512_set(name, value);
				break;
			case AES_128_CBC:
				rc = nvram_aes_cbc_set(name, value);
				break;
			default:
				rc = nvram_set(name, value);
				break;
			}
		}
		break;
	case CMD_UNSET:
		if (argc > 0)
			rc = nvram_unset(*argv);
		break;
	case CMD_COMMIT:
		rc = nvram_commit();
		break;
	case CMD_SHOW:
		rc = nvram_getall(buf, sizeof(buf));
		for (name = buf; *name; name += strlen(name) + 1)
			puts(name);
		break;
	case CMD_FSET:
		do {
			char *line = NULL;
			size_t len = 0;
			FILE *f = (argc > 0) ? fopen(*argv, "r") : stdin;

			if (f == NULL)
				break;
			while (TEMP_FAILURE_RETRY(getline(&line, &len, f)) != -1)
				nvram_put(line);
			if (f != stdin)
				fclose(f);
			free(line);
			rc = 0;
		} while (0);
		break;
	case CMD_POPULATE:
		rc = nvram_load(*argv, buf);
		if (!rc) {
			for (p = buf + sizeof(*nh); *p; p += strlen(p) + 1) {
				name = strsep(&p, "=");
				nvram_set(name, p);
			}
			nh = (struct nvram_header *)buf;
			if (nh->kern_start && nh->rootfs_start)
				nvram_put("x_sys_bootm=0x%x,0x%x", nh->kern_start, nh->rootfs_start);
		} else
			fprintf(stderr, "%d\n", rc);
		break;
	case CMD_PRINT:
		for (rc = 0; argc-- > 0; argv++) {
			if (!(value = nvram_get(*argv)))
				continue;
			printf("%s='", *argv);
			for (p = value; (c = *value++) != '\0'; ) {
				if (c == '\'') {
					printf("%.*s'\\''", (int)(value - p) - 1, p);
					p = value;
				}
			}
			printf("%.*s'\n", (int)(value - p), p);
		}
		break;
	default:
		break;
	}

	exit(rc ? EXIT_FAILURE : EXIT_SUCCESS);
}
