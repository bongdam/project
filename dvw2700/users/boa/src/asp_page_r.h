#ifndef __ASP_PAGE_R_H
#define __ASP_PAGE_R_H

#include <alloca.h>

char *req_fget_cstream_var(request *req, const char *fmt, ...);

int rqst_buffer_grow(request *req, size_t count);
int rqst_write(request *req, const void *buf, size_t count);

static inline __attribute__((always_inline)) int rqst_putc(request *req, int c)
{
	if ((req->max_buffer_size <= req->buffer_end) && rqst_buffer_grow(req, 1))
		return -1;
	req->buffer[req->buffer_end++] = c;
	return 1;
}

#ifdef CSRF_SECURITY_PATCH
void log_boaform(char *form, request *req);
#endif	/* CSRF_SECURITY_PATCH */

#ifdef CONFIG_APP_FWD
extern int isCountDown;
extern int isFWUPGRADE;
#endif	/* CONFIG_APP_FWD */
#endif	/* __ASP_PAGE_R_H */
