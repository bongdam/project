#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include "../../../cpkg/user/include/dvflag.h"

static unsigned int ntp_sync;

#if defined(CONFIG_GUNZIP) && defined(CONFIG_GZIP)
#define COMPRESS_SYSLOG 1
#else
#define COMPRESS_SYSLOG 0
#endif

#define USE_FEATURE_VOLATILE_LOG(...)	__VA_ARGS__
#define ENABLE_FEATURE_VOLATILE_LOG 1

static int Pwrite(void *t, const char *command,
		  FILE *(*_open)(const char *, const char *),
		  int (*_close)(FILE *),
		  ssize_t (*twrite)(const void *, size_t, size_t, void *))
{
	char buf[0x2000];
	FILE *f;
	int len;

	f = _open(command, "r");
	if (f != NULL) {
		while ((len = fread(buf, 1, sizeof(buf), f)) > 0)
			twrite(buf, 1, len, t);
		_close(f);
	}

	return (f) ?  0 : -1;
}

static ssize_t clone_write(const void *ptr, size_t size, size_t nmemb, int fd)
{
	return safe_write(fd, ptr, size * nmemb);
}

#if defined(CONFIG_GUNZIP) && defined(CONFIG_GZIP)
#define KB * 1024
#ifndef MAXLINE
#define MAXLINE	4096
#endif
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)
#endif

/* size of control buffer to send/recv one file descriptor */
#define	CONTROLLEN	CMSG_LEN(sizeof(int))

static const char *usocknam = "/var/slogd.sock";
static struct cmsghdr *cmptr = NULL;	/* malloc'ed first time */

/*
   touch tmpfile
   IF exist(msg.gz)
     IF len(msg.gz) > 32KB
       rename(msg.gz, msg.gz.0)
     ELSE
       gunzip(msg.gz) | gzip > tmpfile
     FI
   FI
   cat(plain_msg) | gzip >> tmpfile
   rename(tmpfile, msg.gz)
 */
static int gzip_append(const char *gzfilp, const char *filp)
{
	char command[128], tmplat[] = "/var/log/XXXXXX";
	FILE *t;
	int fd, rc = 0;
	struct stat stat_buf;

	if (!gzfilp || !gzfilp[0])
		return -1;

	if (!filp || lstat(filp, &stat_buf))
		return -1;

	fd = mkstemp(tmplat);
	if (fd < 0)
		return -1;
	close(fd);

	snprintf(command, sizeof(command), "gzip >%s", tmplat);
	t = popen(command, "w");
	if (t == NULL)
		return -1;

	if (!lstat(gzfilp, &stat_buf) && stat_buf.st_size) {
		if (stat_buf.st_size < 32 KB) {
			snprintf(command, sizeof(command), "gunzip -c %s", gzfilp);
			rc = Pwrite(t, command, popen, pclose, (void *)fwrite);
		} else {
			int i = strlen(gzfilp) + 3;
			char swpnam[i];

			sprintf(swpnam, "%s.0", gzfilp);
			rename(gzfilp, swpnam);
			unlink(gzfilp);
		}
	}

	if (!rc)
		rc = Pwrite(t, filp, fopen, fclose, (void *)fwrite);

	pclose(t);

	if (!rc)
		rc = rename(tmplat, gzfilp);
	//if (rc)
		unlink(tmplat);
	return rc;
}

/*
 * Receive a file descriptor from a server process.  Also, any data
 * received is passed to (*_usrfunc)(STDERR_FILENO, buf, nbytes).
 * We have a 2-byte protocol for receiving the fd from send_fd().
 */
static int recv_fd(int fd, ssize_t (*_usrfunc)(int, const void *, size_t))
{
	int newfd = -1, nr, status;
	char *p;
	char buf[MAXLINE];
	struct iovec iov[1];
	struct msghdr msg;

	status = -1;
	for (;;) {
		iov[0].iov_base = buf;
		iov[0].iov_len = sizeof(buf);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		if (cmptr == NULL && (cmptr = malloc(CONTROLLEN)) == NULL)
			return -1;
		msg.msg_control = cmptr;
		msg.msg_controllen = CONTROLLEN;
		if ((nr = recvmsg(fd, &msg, 0)) < 0) {
			perror("recvmsg error");
			return -1;
		} else if (nr == 0) {
			perror("connection closed by server");
			return -1;
		}

		/*
		 * See if this is the final data with null & status.  Null
		 * is next to last byte of buffer; status byte is last byte.
		 * Zero status means there is a file descriptor to receive.
		 */
		for (p = buf; p < &buf[nr];) {
			if (*p++ == 0) {
				if (p != &buf[nr - 1]) {
					fprintf(stderr, "message format error\n");
					return -1;
				}
				status = *p & 0xFF;	/* prevent sign extension */
				if (status == 0) {
					if (msg.msg_controllen < CONTROLLEN) {
						fprintf(stderr, "status = 0 but no fd\n");
						return -1;
					}
					newfd = *(int *)CMSG_DATA(cmptr);
				} else {
					newfd = -status;
				}
				nr -= 2;
			}
		}
		if (nr > 0 && (*_usrfunc)(STDERR_FILENO, buf, nr) != nr)
			return -1;
		if (status >= 0)	/* final data has arrived */
			return newfd;	/* descriptor, or -status */
	}
}

static ssize_t write_html(const void *ptr, size_t size, size_t nmemb, int fd)
{
	char *q, tmp[BUFSIZ];
	const char *p = ptr;
	size_t i, pending;

	nmemb *= size;
	q = tmp;
	pending = 0;
	for (i = 0; i < nmemb; i++, p++) {
		switch (*p) {
		case '<':
			*q++ = '&';
			*q++ = 'l';
			*q++ = 't';
			*q++ = ';';
			pending += 4;
			break;
		case '>':
			*q++ = '&';
			*q++ = 'g';
			*q++ = 't';
			*q++ = ';';
			pending += 4;
			break;
		case '&':
			*q++ = '&';
			*q++ = 'a';
			*q++ = 'm';
			*q++ = 'p';
			*q++ = ';';
			pending += 5;
			break;
		case '\"':
			*q++ = '&';
			*q++ = 'q';
			*q++ = 'u';
			*q++ = 'o';
			*q++ = 't';
			*q++ = ';';
			pending += 6;
			break;
		default:
			*q++ = *p;
			pending += 1;
			break;
		}

		if (pending >= (sizeof(tmp) - 6)) {
			if (safe_write(fd, tmp, pending) != pending)
				return -1;
			q = tmp;
			pending = 0;
		}
	}

	if (pending > 0 && (safe_write(fd, tmp, pending) != pending))
		return -1;

	return nmemb;
}

static int recvfd_n_writepage(int s, const char *gzfilp, const char *filp)
{
	int fd;
	char command[128];
	struct stat statbuf;

	fd = recv_fd(s, safe_write);
	if (fd > -1) {
		int flags = fcntl(fd, F_GETFL, 0);
		if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK))
			perror("fcntl");
		dprintf(fd,
			"<!DOCTYPE html>\n"
			"<html>\n"
			"<head>\n"
			"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n"
			"<title>LOG</title>\n"
			"<style>\n"
			"pre {\n"
			"display: block;\n"
			"font-family: monospace;\n"
			"white-space: pre;\n"
			"margin: 1em 0;\n"
			"}\n"
			"</style>\n"
			"</head>\n"
			"<body>\n"
			"<pre>\n");

		snprintf(command, sizeof(command), "%s.0", gzfilp);
		if (!lstat(command, &statbuf) && statbuf.st_size > 0) {
			snprintf(command, sizeof(command), "gunzip -c %s.0", gzfilp);
			Pwrite((void *)fd, command, popen, pclose, (void *)write_html);
		}

		if (!lstat(gzfilp, &statbuf) && statbuf.st_size > 0) {
			snprintf(command, sizeof(command), "gunzip -c %s", gzfilp);
			Pwrite((void *)fd, command, popen, pclose, (void *)write_html);
		}

		Pwrite((void *)fd, filp, fopen, fclose, (void *)write_html);

		dprintf(fd, "</pre>\n" "</body>\n" "</html>\n");
		close(fd);
	}
	close(s);
	return 0;
}

static int serv_listen(void)
{
	int fd, err, rval, len;
	struct sockaddr_un un;

	if (strlen(usocknam) >= sizeof(un.sun_path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	/* create a UNIX domain stream socket */
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return (-2);

	unlink(usocknam);		/* in case it already exists */

	/* fill in socket address structure */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, usocknam);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(usocknam);

	/* bind the name to the descriptor */
	if (bind(fd, (struct sockaddr *)&un, len) < 0) {
		rval = -3;
		goto errout;
	}

	if (listen(fd, 10) < 0) {	/* tell kernel we're a server */
		rval = -4;
		goto errout;
	}

	return (fd);

errout:
	err = errno;
	close(fd);
	errno = err;
	return (rval);
}
#endif	/* CONFIG_GUNZIP && CONFIG_GZIP */

static unsigned int ntpstate(void)
{
	int fd = open("/proc/dvflag", O_RDWR);
	if (fd > -1) {
		read(fd, (void *)&ntp_sync, sizeof(ntp_sync));
		close(fd);
	}
	return ntp_sync;
}

static void volatile_log_locally(const char *path, int capsize, char *msg)
{
	struct flock fl;
	struct stat statf;
	int fd, regular, cursize, len = strlen(msg);
 reopen:
	fd = open(path, O_RDWR | O_CREAT
			| O_NOCTTY | O_APPEND | O_NONBLOCK, 0666);
	if (fd < 0)
		return;

	regular = (fstat(fd, &statf) == 0 && S_ISREG(statf.st_mode));
	cursize = statf.st_size;

	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 1;
	fl.l_type = F_WRLCK;
	fcntl(fd, F_SETLKW, &fl);

	if (regular && (cursize > capsize)) {
		char newpath[strlen(path) + sizeof ".XXXXXX" ];
		int newfd, uphalf;
		char *p, *q;

		sprintf(newpath, "%s.XXXXXX", path);
		newfd = mkstemp(newpath);
		if (newfd > -1) {
			capsize /= 2;
			lseek(fd, capsize, SEEK_SET);
			uphalf = cursize - capsize;
			p = (char *)malloc(uphalf + 1);
			if (p != NULL) {
				read(fd, p, uphalf);
				p[uphalf] = '\0';
				for (q = p; *q && *q != '\n'; q++)
					uphalf--;
				if (uphalf > 1)
					write(newfd, &q[1], uphalf - 1);
				free(p);
				rename(newpath, path);
				fl.l_type = F_UNLCK;
				fcntl(fd, F_SETLKW, &fl);
				close(fd);
				close(newfd);
				goto reopen;
			}
			unlink(newpath);
			close(newfd);
		}
	}

	full_write(fd, msg, len);
	fl.l_type = F_UNLCK;
	fcntl(fd, F_SETLKW, &fl);
	close(fd);
}
