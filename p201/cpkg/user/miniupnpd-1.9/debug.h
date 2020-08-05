#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include <stdarg.h>
#ifdef SYSLOG
#include <syslog.h>
#endif

extern unsigned short Lmask;
void say(const char *fmt, ...);

#ifdef SYSLOG
# define LOG(pri, fmt, args...)				\
	do {						\
		if (Lmask & (1 << pri)) 		\
			syslog(pri, fmt, ## args); 	\
	} while(0)

# define OPEN_LOG(ident, opt, fac) openlog(ident, opt, fac)
# define CLOSE_LOG() closelog()
#else
/* sys/syslog.h */
# define LOG_EMERG       0       /* system is unusable */
# define LOG_ALERT       1       /* action must be taken immediately */
# define LOG_CRIT        2       /* critical conditions */
# define LOG_ERR         3       /* error conditions */
# define LOG_WARNING     4       /* warning conditions */
# define LOG_NOTICE      5       /* normal but significant condition */
# define LOG_INFO        6       /* informational */
# define LOG_DEBUG       7       /* debug-level messages */

# define LOG(pri, fmt, args...)				\
	do {						\
		if (Lmask & (1 << pri)) 		\
			say(fmt, ## args); 		\
	} while(0)

# define OPEN_LOG(ident, opt, fac) do {} while(0)
#define CLOSE_LOG() do {} while(0)
#endif

#ifdef DEBUG
# undef DEBUG
# define DEBUG(fmt, args...) LOG(LOG_DEBUG, fmt, ## args)
#else
# define DEBUG(fmt, args...) do {} while(0)
#endif

#endif
