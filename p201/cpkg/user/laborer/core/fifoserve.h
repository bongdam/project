#ifndef __fifoserve_h_
#define __fifoserve_h_

#include <stdarg.h>

int open_reply_pipe(char *pipe_name);
void fifo_reply(int fd, char *fmt, ...);

#endif	/* __fifoserve_h_ */
