#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <libytool.h>
#include <shutils.h>
#include <bcmnvram.h>
#include <dvflag.h>
#include <brdio.h>
#include "furl.h"

#define in_range(c, lo, up)  ((int)(c) >= lo && (int)(c) <= up)
#define isdigit(c) in_range(c, '0', '9')
#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))

#define MAX_TIMEO   4000

extern char *strcasestr(const char *haystack, const char *needle);
int do_wget(struct fwstat *fbuf, int *exp, int timeo, const char *url);

static char *xnvram_get(const char *name)
{
	return nvram_get(name) ? : ({ exit(1); NULL; });
}

static inline const char *skip_leading(const char *s)
{
	while (isspace(*s))
		s++;
	return s;
}

static inline char *trim_trailing(char *s)
{
	if (s[0]) {
		char *end = s + strlen(s) - 1;
		while (end >= s && isspace(*end))
			end--;
		*(end + 1) = '\0';
	}
	return s;
}

char *strsubchr(char *src, const char *reject)
{
	char *p, *dst = src;
	const char *q;
	int ch;

	for (p = src; (ch = *p); p++) {
		for (q = reject; *q && (ch != *q); q++) ;
		if (!*q)
			*dst++ = ch;
	}
	*dst = '\0';
	return src;
}

static char *strtrim_dup(const char *s, const char *exclude)
{
	char *p = strdup(s);
	return ystrtrim(p, exclude);
}

static char *xbuild_url(const char *f)
{
	char *p, *q, *url;
	p = strtrim_dup(xnvram_get("fota_url"), " /\f\n\r\t\v");
	q = strtrim_dup(f, " /\f\n\r\t\v");
	url = malloc(strlen(p) + strlen(q) + 2);
	sprintf(url, "%s/%s", p, q);
	free(p);
	free(q);
	return url;
}

static int version2num(const char *s)
{
	int m, n, b;

	// "V1.23.45"
	while (!isdigit(*s))
		s++;
	// "1.23.45"
	if (sscanf(s, "%d.%d.%d", &m, &n, &b) == 3)
		return (m * 10000) + (n * 100) + b;
	return -1;
}

/*
  0 < higher
  0   same
  0 > lower
 */
static int cmpver(char *s)
{
	int newver, curver;
	char buf[32];

	newver = version2num(s);
	if (newver == -1)
		return -1;
	if (yfcat("/etc/version", "%*s %31s", buf) < 1)
		return -1;
	if ((curver = version2num(buf)) == -1)
		return -1;
	return (newver - curver);
}

/* attribute-value pair copy operation */
static char *avp_get(const char *s, const char *name, char *dst, size_t len)
{
	char fmt[24];
	char *p = strcasestr(s, name);

	if (!p || (p = strchr(p + strlen(name), '=')) == NULL)
		return NULL;
	snprintf(fmt, sizeof(fmt), "%%%zu[^\n]", len - 1);
	if (sscanf(skip_leading(p + 1), fmt, dst) > 0)
		return trim_trailing(dst);
	return ({ dst[0] = '\0'; dst; });
}

static void exit_fota(int signo)
{
	if (signo)
		killpg(0, SIGKILL);
	exit(signo ? EXIT_FAILURE : EXIT_SUCCESS);
}

int fota_check(int argc, char **argv)
{
	struct fwstat fbuf;
	char buffer[1024], *url;
	char tmp[128];
	int diff, tries = 0;

	signal(SIGTERM, exit_fota);
	url = xbuild_url(nvram_get("fota_cfgfile") ? : "update.p201");
	memset(&fbuf, 0, sizeof(fbuf));
	fbuf.fmem = buffer;
	fbuf.caplen = sizeof(buffer) - 1;
	do {
		if (!do_wget(&fbuf, &tries, MAX_TIMEO, url)) {
			buffer[fbuf.rcvlen] = '\0';
			if (!avp_get(buffer, "Version", tmp, sizeof(tmp)))
				break;
			diff = cmpver(tmp);
			if (!avp_get(buffer, "ImageName", tmp, sizeof(tmp)))
				break;
			free(url);
			printf("%d %s\n", diff, ydespaces(tmp));
			exit_fota(0);
		} else
			exit(fbuf.lasterror ? : -1);
	} while (0);

	free(url);
	exit(EXIT_FAILURE);
}
