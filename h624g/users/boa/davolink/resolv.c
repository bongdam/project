#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "apmib.h"
#include "custom.h"

/* @note: APNRTL-287 */
int set_opt_dns(FILE *f)
{
	struct nameserver_addr ns_addrs[2];
	int i, n;

	n = sort_nameserver("/etc/resolv.conf", ns_addrs, _countof(ns_addrs),
			    AF_INET);
	for (i = 0; i < n; i++)
		fprintf(f, "opt dns %u.%u.%u.%u\n", NIPQUAD(ns_addrs[i].na_addr));
	return (i > 0) ? 0 : 1;
}

#ifdef CONFIG_FILE_LOCKING
FILE *locked_fopen(const char *path, const char *mode, int wait)
{
	FILE *f = fopen(path, mode);
	struct flock fl;

	if (f != NULL) {
		fl.l_type = strpbrk(mode, "wa") ? F_WRLCK : F_RDLCK;
		fl.l_whence = SEEK_SET;
		fl.l_start = 0;
		fl.l_len = 0;
		fl.l_pid = getpid();
		if (fcntl(fileno(f), wait ? F_SETLKW : F_SETLK, &fl)) {
			fclose(f);
			f = NULL;
		}
	}
	return f;
}

void locked_fclose(FILE * f)
{
	struct flock fl;

	if (f != NULL) {
		fl.l_type = F_UNLCK;
		fl.l_whence = SEEK_SET;
		fl.l_start = 0;
		fl.l_len = 0;
		fl.l_pid = getpid();
		if (fcntl(fileno(f), F_SETLK, &fl))
			perror("F_UNLCK");
		fclose(f);
	}
}
#else
FILE *locked_fopen(const char *path, const char *mode, int wait)
{
	return fopen(path, mode);
}

void locked_fclose(FILE * f)
{
	if (f != NULL)
		fclose(f);
}
#endif

static int is_inet_ns(struct nameserver_addr *addr, void *unused)
{
	return (addr->na_family == AF_INET) ? 0 : -1;
}

static int is_inet6_ns(struct nameserver_addr *addr, void *unused)
{
	return (addr->na_family == AF_INET6) ? 0 : -1;
}

static int false_ns(struct nameserver_addr *addr, void *unused)
{
	return -1;
}

static int grep_nameserver(FILE * f, struct nameserver_addr *addr,
			   int len, struct abuffer *other,
			   int (*compar) (struct nameserver_addr *, void *),
			   void *data)
{
	char *p, buf[128];
	int n = 0;

	while (fgets(buf, sizeof(buf), f) && n < len) {
		ydespaces(buf);
		if (!strncmp(buf, "nameserver", sizeof "nameserver" - 1) &&
		    isspace(buf[sizeof "nameserver" - 1])) {
			ydespaces(p = &buf[sizeof "nameserver"]);
			if (p == '\0')
				continue;
			memset(addr, 0, sizeof(*addr));
			addr->na_family = (strchr(p, ':')) ? AF_INET6 : AF_INET;
			if (inet_pton(addr->na_family, p, &addr->na_addr6) == 1 &&
			    (compar == NULL || !compar(addr, data))) {
				addr++;
				n++;
			}
		} else if (other != NULL) {
			aprintf(other, "%s ", buf);
			other->buf[other->count - 1] = '\0';
		}
	}

	return n;
}

int commit_nameserver(const char *path, struct nameserver_addr *addr,
		      int len, int domain)
{
	FILE *f;
	char str[INET6_ADDRSTRLEN];
	struct nameserver_addr tmp[8];
	struct nameserver_addr *nsv[2];
	int i, ii, count[_countof(nsv)] = { 0 };
	struct abuffer m;
	char *p;

	if (addr == NULL || len < 0)
		return -1;

	f = locked_fopen(path, "a+", 1);
	if (f == NULL)
		return -1;

	if (init_abuffer(&m, 128) == NULL)
		goto out;

	if (domain == AF_INET) {
		nsv[0] = addr;
		count[0] = len;
		nsv[1] = &tmp[0];
		count[1] = grep_nameserver(f, tmp, _countof(tmp),
					   &m, is_inet6_ns, NULL);
	} else if (domain == AF_INET6) {
		nsv[1] = addr;
		count[1] = len;
		nsv[0] = &tmp[0];
		count[0] = grep_nameserver(f, tmp, _countof(tmp),
					   &m, is_inet_ns, NULL);
	} else {
		nsv[0] = addr;
		count[0] = len;
		grep_nameserver(f, tmp, _countof(tmp), &m, false_ns, NULL);
	}

	for (i = 0; i < 2; i++) {
		if (count[i] <= 0)
			continue;
		count[i] = rmdup_nameserver(nsv[i], count[i]);
	}

	rewind(f);
	ftruncate(fileno(f), 0);

	for (i = 0; i < _countof(nsv); i++) {
		addr = nsv[i];
		for (ii = 0; ii < count[i]; ii++) {
			if (inet_ntop(addr[ii].na_family,
				&addr[ii].na_addr6, str, INET6_ADDRSTRLEN))
				fprintf(f, "nameserver %s\n", str);
		}
	}

	for (p = m.buf; *p; p += (strlen(p) + 1))
		fprintf(f, "%s\n", p);

 out:
	fini_abuffer(&m);
	locked_fclose(f);
	return 0;
}

int rmdup_nameserver(struct nameserver_addr *addr, int len)
{
	int i, n, newlen = 1;

	if (addr == NULL || len < 2)
		return len;

	for (i = 1; i < len; i++) {
		for (n = 0; n < newlen; n++) {
			if (addr[i].na_family == addr[n].na_family &&
			    !memcmp(&addr[i].na_addr6, &addr[n].na_addr6,
				    (addr[i].na_family == AF_INET) ?
				    sizeof(addr[0].na_addr) : sizeof(addr[0].na_addr6)))
				break;
		}
		if (n == newlen)
			addr[newlen++] = addr[i];
	}

	return newlen;
}

int sort_nameserver(const char *path, struct nameserver_addr *addrp,
		    int len, int domain)
{
	FILE *f;
	int n, count;

	if (addrp == NULL || len < 1)
		return 0;

	f = fopen(path, "r");
	if (f == NULL)
		return 0;

	if (domain == AF_INET)
		count = grep_nameserver(f, addrp, len, NULL, is_inet_ns, NULL);
	else if (domain == AF_INET6)
		count = grep_nameserver(f, addrp, len, NULL, is_inet6_ns, NULL);
	else
		count = grep_nameserver(f, addrp, len, NULL, NULL, NULL);

	n = rmdup_nameserver(addrp, count);
	fclose(f);

	return n;
}

int commit_search(const char *path, char *domains)
{
	FILE *f;
	char buf[256], *p;
	struct abuffer m;

	f = locked_fopen(path, "a+", 1);
	if (f == NULL)
		return -1;

	if (init_abuffer(&m, 128) == NULL)
		goto out;

	while (fgets(buf, sizeof(buf), f)) {
		ydespaces(buf);
		if (!strncmp(buf, "search", sizeof "search" - 1) &&
		    isspace(buf[sizeof "search" - 1])) {
			ydespaces((p = &buf[sizeof "search"]));
			if (!strcmp(domains, p))
				goto out;
		} else {
			aprintf(&m, "%s ", buf);
			m.buf[m.count - 1] = '\0';
		}
	}

	rewind(f);
	ftruncate(fileno(f), 0);
	for (p = m.buf; *p; p += (strlen(p) + 1))
		fprintf(f, "%s\n", p);
	fprintf(f, "search %s\n", domains);
out:
	fini_abuffer(&m);
	locked_fclose(f);
	return 0;
}
