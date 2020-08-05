#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#define USAGE \
    "Telnetd listens for incoming TELNET connections on PORT.\n"\
    "Options:\n" \
    "\t-p PORT\tlisten for connections on PORT (default 23)\n"\
    "\t-l LOGIN\texec LOGIN on connect (default /bin/sh)\n"\
    "\t-f issue_file\tDisplay issue_file instead of /etc/issue.\n"

#define NAME  "telnetd"

extern void bb_show_usage(void)
{
	fflush(stdout);
	fprintf(stderr, USAGE);
	exit(-10);
}

extern void bb_verror_msg(const char *s, va_list p)
{
	fflush(stdout);
	fprintf(stderr, "%s: ", NAME);
	vfprintf(stderr, s, p);
}

extern void bb_error_msg_and_die(const char *s, ...)
{
	va_list p;

	va_start(p, s);
	bb_verror_msg(s, p);
	va_end(p);
	putc('\n', stderr);
	exit(-1);
}

extern void bb_perror_msg_and_die(const char *s, ...)
{
	va_list p;
	int err = errno;

	va_start(p, s);

	if (s == 0)
		s = "";
	bb_verror_msg(s, p);
	if (*s)
		s = ":";
	fprintf(stderr, "%s%s\n", s, strerror(err));

	va_end(p);
	putc('\n', stderr);
	exit(-1);
}

#include <sys/param.h>		/* MAXHOSTNAMELEN */
#include <stdio.h>
#include <unistd.h>

#include <sys/utsname.h>
#include <time.h>

#define LOGIN " login: "

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN  64
#endif

static const char fmtstr_d[] = "%A, %d %B %Y";
static const char fmtstr_t[] = "%H:%M:%S";

void print_login_issue(const char *issue_file, const char *tty)
{
	FILE *fd;
	int c;
	char buf[256];
	const char *outbuf;
	time_t t;
	struct utsname uts;

	time(&t);
	uname(&uts);

	puts("\r");		/* start a new line */

	if ((fd = fopen(issue_file, "r"))) {
		while ((c = fgetc(fd)) != EOF) {
			outbuf = buf;
			buf[0] = c;
			if (c == '\n') {
				buf[1] = '\r';
				buf[2] = 0;
			} else {
				buf[1] = 0;
			}
			if (c == '\\' || c == '%') {
				c = fgetc(fd);
				switch (c) {
				case 's':
					outbuf = uts.sysname;
					break;

				case 'n':
					outbuf = uts.nodename;
					break;

				case 'r':
					outbuf = uts.release;
					break;

				case 'v':
					outbuf = uts.version;
					break;

				case 'm':
					outbuf = uts.machine;
					break;

				case 'D':
				case 'o':
					getdomainname(buf, sizeof(buf));
					buf[sizeof(buf) - 1] = '\0';
					break;
				case 'd':
					strftime(buf, sizeof(buf), fmtstr_d, localtime(&t));
					break;

				case 't':
					strftime(buf, sizeof(buf), fmtstr_t, localtime(&t));
					break;

				case 'h':
					gethostname(buf, sizeof(buf) - 1);
					break;

				case 'l':
					outbuf = tty;
					break;

				default:
					buf[0] = c;
				}
			}
			fputs(outbuf, stdout);
		}

		fclose(fd);

		fflush(stdout);
	}
}
