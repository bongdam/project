#include <arpa/inet.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <libytool.h>
#include <bcmnvram.h>
#include <fcntl.h>

#define LISTENQ  20  /* second argument to listen() */
#define MAXLINE 1024   /* max length of a line */
#define RIO_BUFSIZE 1024

int default_port = 876;
int DEBUG = 0;

typedef struct {
	int rio_fd;                 /* descriptor for this buf */
	int rio_cnt;                /* unread byte in this buf */
	char *rio_bufptr;           /* next unread byte in this buf */
	char rio_buf[RIO_BUFSIZE];  /* internal buffer */
} rio_t;

/* Simplifies calls to bind(), connect(), and accept() */
typedef struct sockaddr SA;

typedef struct {
	char filename[512];
	off_t offset;              /* for support Range */
	size_t end;
} http_request;

typedef struct {
	const char *extension;
	const char *mime_type;
} mime_map;

mime_map meme_types [] = {
	{".css", "text/css"},
	{".gif", "image/gif"},
	{".htm", "text/html"},
	{".html", "text/html"},
	{".jpeg", "image/jpeg"},
	{".jpg", "image/jpeg"},
	{".ico", "image/x-icon"},
	{".js", "text/javascript"},
	{".pdf", "application/pdf"},
	{".mp4", "video/mp4"},
	{".png", "image/png"},
	{".svg", "image/svg+xml"},
	{".xml", "text/xml"},
	{NULL, NULL},
};

char *default_mime_type = "text/plain";

void rio_readinitb(rio_t *rp, int fd)
{
	rp->rio_fd = fd;
	rp->rio_cnt = 0;
	rp->rio_bufptr = rp->rio_buf;
}

ssize_t writen(int fd, void *usrbuf, size_t n)
{
	size_t nleft = n;
	ssize_t nwritten;
	char *bufp = usrbuf;

	while (nleft > 0) {
		if ((nwritten = write(fd, bufp, nleft)) <= 0) {
			if (errno == EINTR)  /* interrupted by sig handler return */
				nwritten = 0;    /* and call write() again */
			else
				return -1;       /* errorno set by write() */
		}
		nleft -= nwritten;
		bufp += nwritten;
	}
	return n;
}

/*
 * rio_read - This is a wrapper for the Unix read() function that
 *    transfers min(n, rio_cnt) bytes from an internal buffer to a user
 *    buffer, where n is the number of bytes requested by the user and
 *    rio_cnt is the number of unread bytes in the internal buffer. On
 *    entry, rio_read() refills the internal buffer via a call to
 *    read() if the internal buffer is empty.
 */

static ssize_t rio_read(rio_t *rp, char *usrbuf, size_t n)
{
	int cnt;
	while (rp->rio_cnt <= 0) {  /* refill if buf is empty */
		rp->rio_cnt = read(rp->rio_fd, rp->rio_buf, sizeof(rp->rio_buf));
		if (rp->rio_cnt < 0) {
			if (errno != EINTR) /* interrupted by sig handler return */
				return -1;
		}
		else if (rp->rio_cnt == 0)  /* EOF */
			return 0;
		else
			rp->rio_bufptr = rp->rio_buf; /* reset buffer ptr */
	}

	/* Copy min(n, rp->rio_cnt) bytes from internal buf to user buf */
	cnt = n;
	if (rp->rio_cnt < n)
		cnt = rp->rio_cnt;
	memcpy(usrbuf, rp->rio_bufptr, cnt);
	rp->rio_bufptr += cnt;
	rp->rio_cnt -= cnt;
	return cnt;
}

/*
 * rio_readlineb - robustly read a text line (buffered)
 */
ssize_t rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen)
{
	int n, rc;
	char c, *bufp = usrbuf;

	for (n = 1; n < maxlen; n++) {
		if ((rc = rio_read(rp, &c, 1)) == 1) {
			*bufp++ = c;
			if (c == '\n')
				break;
		} else if (rc == 0) {
			if (n == 1)
				return 0; /* EOF, no data read */
			else
				break;    /* EOF, some data was read */
		} else
			return -1;    /* error */
	}

	*bufp = '\0';
	return n;
}

void handle_directory_request(int out_fd)
{
	char buf[MAXLINE];

	sprintf(buf, "HTTP/1.1 200 OK\r\n" \
			"Content-Type: text/html\r\n\r\n");
	writen(out_fd, buf, strlen(buf));

	sprintf(buf, "<html lang=\"ko\">\n" \
					"<head>\n" \
  					"<meta charset=\"utf-8\" />\n" \
  					"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\" />\n" \
  					"<meta http-equiv=\"cache-control\" content=\"max-age=0\" />\n" \
  					"<meta http-equiv=\"cache-control\" content=\"no-cache\" />\n" \
  					"<meta http-equiv=\"expires\" content=\"-1\" />\n" \
  					"<meta http-equiv=\"expires\" content=\"Tue, 01 Jan 1980 1:00:00 GMT\" />\n" \
  					"<meta http-equiv=\"pragma\" content=\"no-cache\" />\n" \
  					"<title>인터넷 접속 제한 서비스</title>\n");
	writen(out_fd, buf, strlen(buf));

	sprintf(buf, "<style type=\"text/css\" charset=\"UTF-8\">\n" \
					"html,body { \n" \
						"width:100%%;height:100%%;\n" \
						"padding:0px;margin:0px;\n" \
						"font-size:20px;\n" \
						"line-height:20px;\n" \
					"} \n" \
					"div { \n" \
						"position:absolute;\n" \
						"width:400px; left:0; right:0; margin-left:auto; margin-right:auto;\n" \
						"height:100px; top: 0; bottom:0; margin-top:auto; margin-bottom:auto;\n" \
					"} \n" \
				"</style>\n" \
				"</head>\n");
	writen(out_fd, buf, strlen(buf));

	sprintf(buf, "<body>\n" \
					"<div>\n" \
					"현재 접속한 단말은 고객님의 AP에 설정하신<br>\n" \
					"인터넷 접속 제한 서비스 기능으로 인해 <br>\n" \
					"인터넷 사용이 불가능한 시간입니다.</div>\n" \
					"</body>\n" \
					"</html>\n");
	writen(out_fd, buf, strlen(buf));
}

static const char* get_mime_type(char *filename)
{
	char *dot = strrchr(filename, '.');
	if(dot) { // strrchar Locate last occurrence of character in string
		mime_map *map = meme_types;
		while(map->extension) {
			if(strcmp(map->extension, dot) == 0)
				return map->mime_type;
			map++;
		}
	}
	return default_mime_type;
}

static int getInAddr(char *interface, struct in_addr *pAddr)
{
    struct ifreq ifr;
    int skfd = 0, found = 0;
    struct sockaddr_in *addr;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
		return 0;

	strcpy(ifr.ifr_name, interface);

	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
		close(skfd);
		return 0;
	}

	if (ioctl(skfd, SIOCGIFADDR, &ifr) == 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*pAddr = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}

	close(skfd);
	return found;
}

int open_listenfd(int port)
{
	int listenfd, optval = 1;
	struct sockaddr_in serveraddr;
	int val = 0;
	struct in_addr intaddr;

	/* Create a socket descriptor */
	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	/* close server socket on exec */
	if (fcntl(listenfd, F_SETFD, 1) < 0)
		return -1;

	/* Eliminates "Address already in use" error from bind. */
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) < 0)
		return -1;

	/* Listenfd will be an endpoint for all requests to port
		on any IP address for this host */
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	yfcat("/var/sys_op", "%d", &val);
	if (val == 0) {
		if (getInAddr("br0", &intaddr))
			serveraddr.sin_addr.s_addr = intaddr.s_addr;
	}
	serveraddr.sin_port = htons((unsigned short)port);

	if (bind(listenfd, (SA *)&serveraddr, sizeof(serveraddr)) < 0)
		return -1;

	/* Make it a listening socket ready to accept connection requests */
	if (listen(listenfd, LISTENQ) < 0)
		return -1;

	return listenfd;
}

void url_decode(char* src, char* dest, int max)
{
	char *p = src;
	char code[3] = { 0 };
	while(*p && --max) {
		if(*p == '%') {
			memcpy(code, ++p, 2);
			*dest++ = (char)strtoul(code, NULL, 16);
			p += 2;
		} else {
			*dest++ = *p++;
		}
	}
	*dest = '\0';
}

void parse_request(int fd, http_request *req)
{
	rio_t rio;
	char buf[MAXLINE], method[MAXLINE], uri[MAXLINE];
	int i;

	req->offset = 0;
	req->end = 0;              /* default */

	rio_readinitb(&rio, fd);
	rio_readlineb(&rio, buf, MAXLINE);

	if (buf[0] != '\n' && buf[1] != '\n')
		buf[0] = '\n';

	sscanf(buf, "%s %s", method, uri); /* version is not cared */
	/* read all */
	while(buf[0] != '\n' && buf[1] != '\n') { /* \n || \r\n */
		rio_readlineb(&rio, buf, MAXLINE);
		if(buf[0] == 'R' && buf[1] == 'a' && buf[2] == 'n') {
			sscanf(buf, "Range: bytes=%lu-%lu", &req->offset, &req->end);
			// Range: [start, end]
			if( req->end != 0) req->end ++;
		}
	}

	char* filename = uri;
	if(uri[0] == '/') {
		filename = uri + 1;
		int length = strlen(filename);
		if (length == 0) {
			filename = ".";
		} else {
			for (i = 0; i < length; ++ i) {
				if (filename[i] == '?') {
					filename[i] = '\0';
					break;
				}
			}
		}
	}
	url_decode(filename, req->filename, MAXLINE);
}

void log_access(int status, struct sockaddr_in *c_addr, http_request *req)
{
	printf("%s:%d %d - %s\n", inet_ntoa(c_addr->sin_addr),
		ntohs(c_addr->sin_port), status, req->filename);
}

void process(int fd, struct sockaddr_in *clientaddr)
{
	int status = 200;

	if (DEBUG)
		printf("accept request, fd is %d, pid is %d\n", fd, getpid());

	http_request req;
	parse_request(fd, &req);
	handle_directory_request(fd);

	if (DEBUG)
		log_access(status, clientaddr, &req);
}

int main(int argc, char** argv)
{
	struct sockaddr_in clientaddr;
	int listenfd, connfd;
	struct timeval tv, *p_tv = NULL;
	fd_set fdset;
	char buf[256];
	char *path = getcwd(buf, 256);
	socklen_t clientlen = sizeof clientaddr;
	int i, opt, count;

	while ((opt = getopt(argc, argv, "p:D")) != -1) {
		switch (opt) {
			case 'p':
				default_port = strtol(optarg, NULL, 10);
				break;
			case 'D':
				DEBUG = 1;
				break;
			default :
				break;
		}
	}

	listenfd = open_listenfd(default_port);
	if (listenfd > 0) {
		if (DEBUG)
			printf("listen on port %d, fd is %d\n", default_port, listenfd);
	} else {
		perror("ERROR");
		exit(listenfd);
	}
	// Ignore SIGPIPE signal, so if browser cancels the request, it
	// won't kill the whole process.
	signal(SIGPIPE, SIG_IGN);

	while(1)
	{
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		p_tv = &tv;

		FD_ZERO(&fdset);
		FD_SET(listenfd, &fdset);
		count = select(listenfd + 1, &fdset, NULL, NULL, p_tv);
		if (count > 0) {
			if (FD_ISSET(listenfd, &fdset)) {
				connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);
				process(connfd, &clientaddr);
				close(connfd);
			}
		} else {
			switch (count) {
				case 0:
					break;
				default:
					if (errno == EINTR)
						continue;
					if (DEBUG)
						printf("select returned %d\n", count);
					break;
			}
		}
	}

	if (listenfd)
		close(listenfd);

	return 0;
}
