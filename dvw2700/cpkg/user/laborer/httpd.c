#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <endian.h>
#include "httpd.h"
#include <arpa/inet.h>
#include <error.h>
#include <sys/signal.h>
#include <itimer.h>
#include <libytool.h>
#include "notice.h"
#include <dvflag.h>
#include "instrument.h"

static int httpd_netconf_cb(struct notice_block_expand *p,
			u_int event, u_int full_event)
{
	union sockaddr_union su;

	full_event &= p->nb.concern;
	if (p->event != full_event) {
		p->event = full_event;
		select_event_getsockname(p->base, &su);
		yexecl(NULL, "%s %d %u.%u.%u.%u:%u",
		       p->script, (full_event != p->nb.concern),
		       NIPQUAD(su.sin.sin_addr), ntohs(su.sin.sin_port));
	}
	return NOTICE_DONE;
}

#define KB * 1024

#define SYNTIMEO 5
#define NOTRXTIMEO 10
#define PAGEPATHMAX 256
#define MAXCONFLINE 255
#define	MAX_BACKLOG 1024
#define MAX_CONTENT_BUCKET (4 KB)
#define RFC1123FMT "%a, %d %b %Y %H:%M:%S GMT"

static int bare_read(struct select_event_base *base, int fd);

struct mime_type {
	char *pattern;
	char *mime_type;
	char *extra_header;
};

static char no_cache[] =
"Cache-Control: no-cache, no-store, must-revalidate\r\n"
"Pragma: no-cache\r\n"
"Expires: 0"
;

static struct mime_type mime_types[] = {
	{ "**.html", "text/html", no_cache },
	{ "**.png", "image/png", NULL  },
	{ "**.css", "text/css", NULL  },
	{ "**.gif", "image/gif", NULL  },
	{ "**.jpg", "image/jpeg", NULL },
	{ "**.js", "text/javascript", NULL },
};

/* Simple shell-style filename matcher.  Only does ? * and **, and multiple
** patterns separated by |.  Returns 1 or 0.
*/
static int match_one(const char *pattern, int patternlen, const char *string)
{
	const char *p;

	for (p = pattern; p - pattern < patternlen; ++p, ++string) {
		if (*p == '?' && *string != '\0')
			continue;
		if (*p == '*') {
			int i, pl;
			++p;
			if (*p == '*') {
				/* Double-wildcard matches anything. */
				++p;
				i = strlen(string);
			} else
				/* Single-wildcard matches anything but slash. */
				i = strcspn(string, "/");
			pl = patternlen - (p - pattern);
			for (; i >= 0; --i)
				if (match_one(p, pl, &(string[i])))
					return 1;
			return 0;
		}
		if (*p != *string)
			return 0;
	}
	if (*string == '\0')
		return 1;
	return 0;
}

static int match(const char *pattern, const char *string)
{
	const char *or;

	for (;;) {
		or = strchr(pattern, '|');
		if (or == (char *)0)
			return match_one(pattern, strlen(pattern), string);
		if (match_one(pattern, or - pattern, string))
			return 1;
		pattern = or + 1;
	}
	return 0;
}

static struct mime_type *mime_match(const char *file)
{
	int i;
	for (i = 0; i < _countof(mime_types); i++)
		if (match(mime_types[i].pattern, file))
			return &mime_types[i];
	return NULL;
}

static ALWAYS_INLINE void timeout_set(struct timeval *res, struct timeval *a, time_t b)
{
	struct timeval __tv = { .tv_sec = b, .tv_usec = 0 };
	timeradd(a, &__tv, res);
}

static NOINLINE ssize_t safe_fgets(webs_t wp, char *s, int size)
{
	int ret;

	timeout_set(&wp->timeo, &event_iterate_jiffy, NOTRXTIMEO);
	clearerr(wp->f);
	if (fgets(s, size, wp->f)) {
		ret = strlen(s);
#ifndef _NDEBUG
		wp->rx_octets += ret;
#endif
		return ret;
	} else if (feof(wp->f))
		return 0;
	else
		return -1;
}

static void putconf(struct config *conf)
{
	if (conf && --conf->refcnt <= 0)
		free(conf);
}

static NOINLINE ssize_t safe_fread(webs_t wp, void *ptr, size_t nmemb)
{
	int ret;

	timeout_set(&wp->timeo, &event_iterate_jiffy, NOTRXTIMEO);
	clearerr(wp->f);
	ret = fread(ptr, 1, nmemb, wp->f);
	if (ret > 0) {
#ifndef _NDEBUG
		wp->rx_octets += ret;
#endif
		return ret;
	} else if (feof(wp->f))
		return 0;
	else
		return -1;
}

static int transact_timeout_callback(long tid, long id)
{
	struct select_event_base *base = select_event_getbyid(id);
	struct timeval present, tv;

	if (base) {
		webs_t wp = (webs_t)base->data;

		getcurrenttime(&present);
		if (timercmp(&wp->timeo, &present, <)) {
			errno = ETIMEDOUT;
			select_event_free(base);
		} else {
			timersub(&wp->timeo, &present, &tv);
			wp->timeout_tid = itimer_creat(base->id,
				(void *)transact_timeout_callback, &tv);
		}
	}

	return 0;
}

static NOINLINE void free_request_line(webs_t wp)
{
	SAFE_FREE(&wp->protover);
	SAFE_FREE(&wp->method);
	SAFE_FREE(&wp->path);
	SAFE_FREE(&wp->uri_unescaped);
}

static ALWAYS_INLINE int end_of_header(webs_t wp, uint16_t *s)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
# define CRLF 0x0a0d
# define BARELF 0x000a
#else
# define CRLF 0x0d0a
# define BARELF 0x0a00
#endif
	return ((*s == CRLF || *s == BARELF) && wp->nl_state == TNL) ? true : false;
}

static webs_t new_request(struct select_event_base *base, int state)
{
	struct timeval tv = { .tv_usec = 0 };
	webs_t wp;

	wp = (webs_t)malloc(sizeof(*wp));
	if (wp == NULL)
		return NULL;

	memset(wp, 0, sizeof(struct request));
	wp->state = state;
	INIT_LIST_HEAD(&wp->rxmsg);
	INIT_LIST_HEAD(&wp->txmsg);
	wp->content_fd = -1;

	if ((wp->f = fdopen(base->fd, "r+")) == NULL) {
		free(wp);
		return NULL;
	}

	timeout_set(&wp->timeo, &event_iterate_jiffy, tv.tv_sec);
#ifndef _NDEBUG
	wp->ctime = wp->timeo;
#endif
	tv.tv_sec = 1;
	wp->timeout_tid = itimer_creat(base->id, (void *)transact_timeout_callback, &tv);

	return wp;
}

static inline int xdigittoi(int c)
{
	return (c <= '9') ?
		(int)(c - '0') : (int)(c + 10 - (islower(c) ? 'a' : 'A'));
}

static char *unescape(const char *src)
{
	struct str dst;
	const char *s;
	unsigned val;
	int c, hex = 0;

	dst.pos = 0;
	dst.size = 128;
	dst.p = malloc(dst.size);

	for (s = src; (c = *s); s++) {
		if (hex-- > 0) {
			if (isxdigit(c)) {
				val = (val << 4) | xdigittoi(c);
				if (!hex) {
					if (!dst.pos)
						str_printf(&dst, "%.*s",
							(int)(s - src - 2), src);
					str_putc(val, &dst);
				}
			} else
				break;
		} else if (c == '%' && ({ val = 0; 1;}))
			hex = 2;
		else if (c == '+') {
			if (dst.pos)
				str_putc(' ', &dst);
			else
				str_printf(&dst, "%.*s ", (s - src), src);
		} else if (dst.pos)
			str_putc(c, &dst);
	}

	if (!dst.pos || c || hex > 0)
		SAFE_FREE(&dst.p);

	return dst.p;
}

static int parse_request(webs_t wp, char *buf, int count)
{
	struct stream_fragment_iterator it;

	wp->cl = wp->cc = 0;
	stream_frag_init_iterator(&wp->rxmsg, &it);
	if (stream_frag_gets(&it, buf, count) <= 0)
		return -1;

	free_request_line(wp);
	if (sscanf(buf, "%ms %ms %ms",
	           &wp->method, &wp->path, &wp->protover) != 3)
		return -1;

	wp->uri_unescaped = unescape(wp->path);

	while (stream_frag_gets(&it, buf, count) > 0) {
		if (buf[0] == '\n' || (buf[0] == '\r' && buf[1] == '\n'))
			break;
		else if (!strncasecmp(buf, "Content-Length:", 15))
			wp->cl = strtoul(ydespaces(&buf[15]), NULL, 0);
	}
	return 0;
}

static int httpd_transact_fdset(struct select_event_base *base, fd_set *rset, fd_set *wset)
{
	webs_t wp = (webs_t)base->data;

	FD_SET(base->fd, rset);
	switch (wp->state) {
	case WRITE:
	case DONE:
	case DEAD:
		FD_SET(base->fd, wset);
	default:
		break;
	}
	return base->fd;
}

static int httpd_transact_read(struct select_event_base *base, int fd)
{
	char buf[MIN_FRAG_SIZE];
	int n = 0;
	webs_t wp = (webs_t)base->data;

	switch (wp->state) {
	case REQ_TOPHALF:
		do {
			n = safe_fgets(wp, buf, sizeof(buf));
			if (n <= 0)
				return n;
			stream_frag_write(&wp->rxmsg, buf, n);
		} while (end_of_header(wp, (uint16_t *)buf) == false &&
		         ({ wp->nl_state = (buf[n - 1] == '\n') ? TNL : NONL; 1;}));

		parse_request(wp, buf, sizeof(buf));
		if (wp->cl > 0)
			wp->state = REQ_BOTTOMHALF;
	/* fall thru */
	case REQ_BOTTOMHALF:
		for (; wp->cl > 0; wp->cl -= n, wp->cc += n) {
			n = safe_fread(wp, buf, sizeof(buf));
			if (n <= 0)
				return n;
			if (wp->cc < MAX_CONTENT_BUCKET)
				stream_frag_write(&wp->rxmsg, buf, n);
		}
		if (wp->cl <= 0)
			wp->state = WRITE;
		break;
	default:
		do {} while ((n = safe_fread(wp, buf, sizeof(buf))) > 0);
	}

	return n;
}

static void put_headers(webs_t wp, int status, char *title,
		char *const extra_headers[], const char *mime_type)
{
#define PROTOCOL "HTTP/1.0"
#define SERVER_NAME "httpd/1.0"

	time_t now;
	char timebuf[100];

	now = time(NULL);
	strftime(timebuf, sizeof(timebuf), RFC1123FMT, gmtime(&now));
	webs_printf(wp, "%s %d %s\r\n", PROTOCOL, status, title);
	webs_printf(wp, "Server: %s\r\n", SERVER_NAME);
	webs_printf(wp, "Date: %s\r\n", timebuf);
	while (extra_headers && *extra_headers) {
		if ((*extra_headers)[0])
			webs_printf(wp, "%s\r\n", *extra_headers);
		extra_headers++;
	}
	if (mime_type != NULL)
		webs_printf(wp, "Content-Type: %s\r\n", mime_type);
	webs_printf(wp, "Connection: close\r\n");
	webs_printf(wp, "\r\n");
}

static int open_page(struct config *conf, const char *path,
		struct stat *sb, struct mime_type **mime)
{
	char *buf;
	int len;

	len = strlen(conf->docuroot) + strlen(path) + sizeof("index.html") + 12;
	buf = alloca(len);
	snprintf(buf, len, "%s%s", conf->docuroot, path);
	if (!stat(buf, sb) && S_ISREG(sb->st_mode)) {
		if (mime)
			*mime = mime_match(strrchr(buf, '/') + 1);
		return open(buf, O_RDONLY);
	} else
 		return -1;
}

static int do_file(webs_t wp)
{
	struct mime_type *mime = NULL;
	struct stat sb = { .st_size = 0 };
	int code = 200;
	char cl[32] = { [0] = '\0' };

	if (!strcasecmp(wp->method, "GET")) {
		if (wp->path && strcmp(wp->path, "/")) {
			wp->content_fd = open_page(wp->conf, wp->path, &sb, &mime);
			if (wp->content_fd < 0 && (wp->conf->feature & SSOP))
				wp->content_fd = open_page(wp->conf, "/index.html", &sb, &mime);
		} else
			wp->content_fd = open_page(wp->conf, "/index.html", &sb, &mime);

		if (wp->content_fd < 0)
			code = 404;
	}

	snprintf(cl, sizeof(cl), "Content-Length: %ld",
		 (wp->content_fd > -1) ? (long)sb.st_size : 0L);

	if (wp->content_fd < 0)
		mime = NULL;

	do {
		char *extras[] = { cl, mime ? mime->extra_header : NULL, NULL, };

		put_headers(wp, code, (code == 404) ? "Not Found" : "Ok",
			extras, mime ? mime->mime_type : NULL);
	} while (0);

	return wp->content_fd;
}

static int httpd_transact_write(struct select_event_base *base, int fd)
{
	webs_t wp = (webs_t)base->data;
	struct stream_fragment *frag;
	int count;

	switch (wp->state) {
	case WRITE:
		do_file(wp);
		wp->state = DONE;

	case DONE:
		while (list_empty(&wp->txmsg) == 0) {
			for (frag = list_entry(wp->txmsg.next, struct stream_fragment, list);
			     (count = stream_frag_pended(frag)) > 0; frag->data += count) {
				count = write(fd, frag->buf + frag->data, count);
				if (count <= 0)
					return count;
#ifndef _NDEBUG
				wp->tx_octets += count;
#endif
			}
			list_del(&frag->list);
			free(frag);
		}

		if (wp->content_fd > -1) {
			char buf[sysconf(_SC_PAGESIZE)];

			for (;;) {
				count = safe_read(wp->content_fd, buf, sizeof(buf));
				if (count > 0) {
					ssize_t n = write(fd, buf, count);
					if (n < count) {
						/* backward */
						lseek(wp->content_fd, (n > 0) ? (n - count) : (0 - count), SEEK_CUR);
						return n;
					}
				} else
					break;
			}
		}
		wp->state = DEAD;
		break;
	case DEAD:
		errno = 0;
		return -1;
	}
	return 0;
}

static int httpd_transact_close(struct select_event_base *base, int fd)
{
	webs_t wp = (webs_t)base->data;

	stream_frag_freeall(&wp->rxmsg);
	stream_frag_freeall(&wp->txmsg);

	free_request_line(wp);
	if (wp->f) {
		fclose(wp->f);
		base->fd = -1;
	}
	if (wp->content_fd > -1)
		close(wp->content_fd);

	putconf(wp->conf);

	free(wp);
	return 0;
}

static struct select_event_operation httpd_transact_op = {
	._fdset = httpd_transact_fdset,
	._read = httpd_transact_read,
	._write = httpd_transact_write,
	._close = httpd_transact_close,
};

#define bare_fdset select_event_fdset_dfl

static int bare_read(struct select_event_base *base, int fd)
{
	int n = 0;

	if (base->data) {
		char buf[MIN_FRAG_SIZE];
		do {} while ((n = read(fd, buf, sizeof(buf))) > 0);
	}
	return n;
}

static struct select_event_operation bare_op = {
	._fdset = bare_fdset,
	._read = bare_read,
};

#define httpd_fdset select_event_fdset_dfl

static int httpd_accept(struct select_event_base *base, int master_fd)
{
	struct select_event_base *transaction;
	webs_t wp;

	transaction = select_event_accept(base, &bare_op, NULL);
	if (transaction == NULL)
		fprintf(stderr, "select_event_accept: %m\n");
	else if ((wp = new_request(transaction, REQ_TOPHALF))) {
		wp->conf = (struct config *)base->data;
		wp->conf->refcnt++;
		select_event_attach(transaction, &httpd_transact_op, (void *)wp);
	}
	return 0;
}

static int httpd_close(struct select_event_base *base, int fd)
{
	struct config *conf = (struct config *)base->data;

	if (conf->nbx.nb.concern) {
		dev_event_chain_deregister(&conf->nbx.nb);
		/* hack for deleting rules if any added */
		conf->nbx.event = 0;
		httpd_netconf_cb(&conf->nbx, 0, conf->nbx.nb.concern);
	}
	putconf(conf);
	return 0;
}

static struct select_event_operation httpd_op = {
	._fdset = httpd_fdset,
	._accept = httpd_accept,
	._close = httpd_close,
};

static int start_httpd(struct ip_addr *bind_address, struct config *conf, int fderr)
{
	struct select_event_base *base;
	union sockaddr_union su;
	struct stat sb;

	base = select_event_socket(AF_INET, SOCK_STREAM, 0);
	if (base != NULL) {
		if (ip_addr2su(&su, bind_address))
			dprintf(fderr, "Invalid address and protocol specified\n");
		else if (select_event_listen(base, &su, &httpd_op,
		                             NULL, MAX_BACKLOG))
			dprintf(fderr, "select_event_listen: %s\n", strerror(errno));
		else {
			if (conf->nbx.script[0] && !stat(conf->nbx.script, &sb)) {
				conf->nbx.nb.notice_call = (notice_fn_t)httpd_netconf_cb;
				conf->nbx.nb.concern = DF_WANLINK | DF_WANIPFILE;
				conf->nbx.nb.priority = 79;
				conf->nbx.base = base;
				conf->nbx.event = conf->nbx.nb.concern & ~dev_event_current();
				httpd_netconf_cb(&conf->nbx, 0, dev_event_current());
				dev_event_chain_register(&conf->nbx.nb);
			}
			return ({ base->data = (void *)conf; 0; });
		}
		select_event_free(base);
	} else
		dprintf(fderr, "select_event_socket: %s\n", strerror(errno));
	return -1;
}

static int select_event_namecmp(struct select_event_base *base, const char *name)
{
	return strncmp(base->name, name, strlen(name));
}

struct select_event_base *select_event_freebyname(const char *fmt, ...)
{
	struct select_event_base *base;
	va_list ap;
	char name[80], *p;

	va_start(ap, fmt);
	p = yvasprintf(name, sizeof(name), fmt, ap);
	va_end(ap);

	if ((base = select_event_iterate((void *)select_event_namecmp, p)))
		select_event_free(base);
	if (p != name)
		free(p);
	return base;
}

/*
Options:
	-p port         Listen port
	-s addr         Binding address
	-d directory    Document root
	-o              Single-serving one page
	-q              Stop serving
	-S script       Script to run
 */
static int mod_httpd(int argc, char **argv, int fd)
{
	struct ip_addr bind_address;
	struct config *conf;
	int opt, quit = 0;

	memset(&bind_address, 0, sizeof(bind_address));
	bind_address.af = AF_INET;
	bind_address.len = 4;
	conf = (struct config *)calloc(sizeof(struct config), 1);
	conf->refcnt = 1;

	optind = 0;	/* reset to 0, rather than the traditional value of 1 */
	while ((opt = getopt(argc, argv, "p:s:d:oqS:")) != -1) {
		switch (opt) {
		case 'q':
			quit = 1;
			break;
		case 'p':
			bind_address.port = htons(strtol(optarg, NULL, 0));
			break;
		case 'o':
			conf->feature |= SSOP;
			break;
		case 'd':
			strlcpy(conf->docuroot, optarg, sizeof(conf->docuroot));
			break;
		case 'S':
			strlcpy(conf->nbx.script, optarg, sizeof(conf->nbx.script));
			break;
		case 's':
			if (inet_pton(bind_address.af, optarg, &bind_address.i_addr) == 1)
				break;
		default:
			free(conf);
			dprintf(fd, "Invalid option\n");
			return 1;
		}
	}

	if (quit)
		select_event_freebyname("tcp://%u.%u.%u.%u:%u/0.0.0.0:*",
		         NIPQUAD(bind_address.i_addr), ntohs(bind_address.port));
	else if (!start_httpd(&bind_address, conf, fd))
		return 0;
	free(conf);
	return (!quit);
}

static void __attribute__((constructor)) register_httpd_module(void)
{
	fifo_cmd_register("httpd",
		"\t[-p port] [-s address] [-d document-root] [-o] [-q]",
		"tiny web server", mod_httpd);
}
