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

#define L_NOLEASE "할당 가능한 IP가 없음."
#define L_LEASEFULL "할당 IP개수를 초과"
#endif
