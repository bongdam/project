#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include <stdarg.h>
#ifdef SYSLOG
#include <syslog.h>
#endif

#ifdef SYSLOG
# define LOG(level, str, args...) do { syslog(level, str, ## args); } while(0)
# define OPEN_LOG(name) openlog(name, 0, 0)
# define CLOSE_LOG() closelog()
#else
# define LOG_EMERG	"EMERGENCY!"
# define LOG_ALERT	"ALERT!"
# define LOG_CRIT	"critical!"
# define LOG_WARNING	"warning"
# define LOG_ERR	"error"
# define LOG_INFO	"info"
# define LOG_DEBUG	"debug"
# define LOG(level, str, args...) do { printf("%s, ", level); \
				printf(str, ## args); \
				printf("\n"); } while(0)
# define OPEN_LOG(name) do {;} while(0)
#define CLOSE_LOG() do {;} while(0)
#endif

#ifdef DEBUG
# undef DEBUG
# define DEBUG(level, str, args...) LOG(level, str, ## args)
# define DEBUGGING
#else
# define DEBUG(level, str, args...) do {;} while(0)
#endif

#ifndef MAX
#define MAX(a, b)	(((int)(a) > (int)(b)) ? (int)(a) : (int)(b))
#define MIN(a, b)	(((int)(a) < (int)(b)) ? (int)(a) : (int)(b))
#endif

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define NQF "%u.%u.%u.%u"

unsigned monotonic_ms(void);
unsigned getmonotime(struct timeval *tvp);
#define monotonic_sec()	getmonotime(NULL)

char *ether_ntoa(unsigned char *haddr);
char *dewhites(char *s);
int wait_for_flags(unsigned int mask, int bwaitall, int timeout);

struct cbuffer {
	char *buf;
	size_t size;
	size_t count;
};

struct double_null_cbuf {
	struct cbuffer cb;
	int argc;
};

int cbprintf(struct cbuffer *m, const char *f, ...);
void nnull_pad(struct double_null_cbuf *nnull);
int nnull_printf(struct double_null_cbuf *nnull, const char *f, ...);

#define L_STARTUP	"\xec\x8b\x9c\xec\x9e\x91\xeb\x90\xa8"
#define L_SENT		"\xeb\xa9\x94\xec\x84\xb8\xec\xa7\x80\xeb\xa5\xbc \xeb\xb3\xb4\xeb\x83\x84"
#define L_SENTFOR	"\xeb\xa9\x94\xec\x84\xb8\xec\xa7\x80 \xeb\xb3\xb4\xeb\x83\x84"
#define L_LEASEFULL	"\xed\x95\xa0\xeb\x8b\xb9 IP\xea\xb0\xaf\xec\x88\x98\xeb\xa5\xbc\xec\xb4\x88\xea\xb3\xbc"
#define L_NOLEASE	"\xed\x95\xa0\xeb\x8b\xb9\xea\xb0\x80\xeb\x8a\xa5\xed\x95\x9c IP\xea\xb0\x80\xec\x97\x86\xec\x9d\x8c"
#define L_USEDIP	"\xeb\x8a\x94 \xec\x82\xac\xec\x9a\xa9\xec\xa4\x91\xec\x9e\x84"
#define L_CLIENT	"\xed\x81\xb4\xeb\x9d\xbc\xec\x9d\xb4\xec\x96\xb8\xed\x8a\xb8"
#define L_RCVFROM	"\xeb\xa9\x94\xec\x84\xb8\xec\xa7\x80 \xeb\xb0\x9b\xec\x9d\x8c"
#define L_RCVED		L_RCVFROM
#define L_ACKED		"\xeb\xa9\x94\xec\x8b\x9c\xec\xa7\x80 \xeb\x8f\x84\xec\xb0\xa9 %s,\xed\x95\xa0\xeb\x8b\xb9\xeb\x90\x9c \xec\x8b\x9c\xea\xb0\x84 %ld"
#define L_RCVED2	"\xeb\xa9\x94\xec\x84\xb8\xec\xa7\x80 \xeb\x8f\x84\xec\xb0\xa9"

/* addon */
#define L_PAUSEDHCPD	"\xec\x84\x9c\xeb\xb2\x84 \xea\xb8\xb0\xeb\x8a\xa5 \xec\xa0\x95\xec\xa7\x80"
#define L_RESUMEDHCPD	"\xec\x84\x9c\xeb\xb2\x84 \xea\xb8\xb0\xeb\x8a\xa5 \xeb\xb3\xb5\xea\xb5\xac"
#endif
