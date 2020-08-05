#ifndef __HTTPD_H
#define __HTTPD_H

#include <syslog.h>
#include <select_event_sock.h>
#include <sys/uio.h>

#include "notice.h"
#include "stream_frag.h"

#undef __GNUC_PREREQ
#if defined __GNUC__ && defined __GNUC_MINOR__
# define __GNUC_PREREQ(maj, min) \
		((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
# define __GNUC_PREREQ(maj, min) 0
#endif

#define PACKED __attribute__ ((__packed__))
#define ALIGNED(m) __attribute__ ((__aligned__(m)))

/* __NO_INLINE__: some gcc's do not honor inlining! :( */
#if __GNUC_PREREQ(3,0) && !defined(__NO_INLINE__)
# define ALWAYS_INLINE __attribute__ ((always_inline)) inline
/* I've seen a toolchain where I needed __noinline__ instead of noinline */
# define NOINLINE      __attribute__((__noinline__))
# if !ENABLE_WERROR
#  define DEPRECATED __attribute__ ((__deprecated__))
#  define UNUSED_PARAM_RESULT __attribute__ ((warn_unused_result))
# else
#  define DEPRECATED
#  define UNUSED_PARAM_RESULT
# endif
#else
# define ALWAYS_INLINE inline
# define NOINLINE
# define DEPRECATED
# define UNUSED_PARAM_RESULT
#endif

#define SSOP (1 << 0)	// single-serve one page
#define MAX_DOCPATH 128
#define MAX_SCRIPTPATH MAX_DOCPATH

struct notice_block_expand {
	struct notice_block nb;		/* MUST be the first */
	unsigned int event;
	struct select_event_base *base;
	char script[MAX_SCRIPTPATH];
};

struct config {
	unsigned int feature;
	char docuroot[MAX_DOCPATH];
	struct notice_block_expand nbx;
	int refcnt;
};

enum req_state {
	REQ_TOPHALF = 0,
	REQ_BOTTOMHALF,
	WRITE,
	DONE,
	DEAD,
};

enum { TNL = 0, NONL };

struct request {
	FILE *f;
	int state, nl_state;
	struct list_head rxmsg, txmsg;
	int content_fd;
	struct timeval timeo;
	long timeout_tid;
	char *method, *path, *protover, *uri_unescaped;
	int cl, cc;	/* content-length, content-cumulative */
	struct config *conf;
#ifndef _NDEBUG
	struct timeval ctime;
	long rx_octets, tx_octets;
#endif
};

typedef struct request *webs_t;

#define webs_printf(wp, fmt, ...)					\
({									\
	ssize_t __n;							\
	__n = stream_frag_printf(&(wp)->txmsg, fmt, ## __VA_ARGS__);	\
	__n;								\
})

#define webs_write(wp, buf, count)					\
({									\
	ssize_t __n;							\
	__n = stream_frag_write(&(wp)->txmsg, buf, count);		\
	__n;								\
})


#define in_range(c, lo, up)  ((int)c >= lo && (int)c <= up)
#define isdigit(c)           in_range(c, '0', '9')
#define isxdigit(c)          (isdigit(c) || in_range(c, 'a', 'f') || in_range(c, 'A', 'F'))
#define islower(c)           in_range(c, 'a', 'z')
#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))

#ifdef __cplusplus
extern "C" {
#endif
static ALWAYS_INLINE void safe_free(char **p)
{
	if (p && *p && ({ free(*p); 1;}))
		*p = NULL;
}

#define SAFE_FREE(p)	safe_free((char **)(p))

extern char *strdupr(char *s, const char *t);

extern void getcurrenttime(struct timeval *tvp);

extern struct select_event_base *select_event_freebyname(const char *fmt, ...);

#ifdef __cplusplus
}
#endif
#endif
