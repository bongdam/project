#ifndef __BBWRAP_H__
#define __BBWRAP_H__

#include <stdarg.h>

#define DEFAULT_SHELL "/bin/sh"
#define MIN(x,y) ((x)>(y)?(y):(x))

extern void bb_show_usage(void);
extern void bb_verror_msg(const char *s, va_list p);
extern void bb_error_msg_and_die(const char *s, ...);
extern void bb_perror_msg_and_die(const char *s, ...);
void print_login_issue(const char *issue_file, const char *tty);

#endif

