/* active server page write instrument
 */
#include "aspvar.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int pwrite_puts(request *req, char *arg)
{
	return req_format_write(req, "%s", arg);
}

int pwrite_itoa(request *req, char *arg)
{
	return req_format_write(req, "%d", *(int *)arg);
}

int pwrite_time_sec(request *req, char *arg)
{
	return req_format_write(req, "%d", *(int *)arg);
}

int pwrite_time_sectomin(request *req, char *arg)
{
	return req_format_write(req, "%d", (*(int *)arg)/60);
}

int pwrite_time_sectohour(request *req, char *arg)
{
	return req_format_write(req, "%d", (*(int *)arg)/3600);
}

int pwrite_time_sectoday(request *req, char *arg)
{
	return req_format_write(req, "%d", (*(int *)arg)/86400);
}

int pwrite_in_ntoa(request *req, char *arg)
{
	struct in_addr addr = { .s_addr = *(in_addr_t *)arg};
	return req_format_write(req, T("%s"), inet_ntoa(addr));
}

int pwrite_in_ntoa2(request *req, char *arg)
{
	struct in_addr addr = { .s_addr = *(in_addr_t *)arg};
    //if (!memcmp(arg, "\x0\x0\x0\x0", 4))
	if (addr.s_addr)
		return req_format_write(req, T("%s"), inet_ntoa(addr));
    else
		return req_format_write(req, T("0.0.0.0"), inet_ntoa(addr));
}

int pwrite_etoa(request *req, char *arg)
{
	unsigned char *p = (unsigned char *)arg;
    
	return req_format_write(req, T("%02x:%02x:%02x:%02x:%02x:%02x"),
				p[0], p[1], p[2], p[3], p[4], p[5]);
}

int pwrite_etoa_without_colon(request *req, char *arg)
{
	unsigned char *p = (unsigned char *)arg;
    
	return req_format_write(req, T("%02x%02x%02x%02x%02x%02x"),
				p[0], p[1], p[2], p[3], p[4], p[5]);
}

int pwrite_puts_webtrans(request *req, char *arg)
{ 
    translate_control_code(arg);
	return req_format_write(req, "%s", arg);
}
