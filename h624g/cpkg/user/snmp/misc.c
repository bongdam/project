#define __MISC_C_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/wireless.h>
#include <signal.h>
#include "defines.h"
#include "misc.h"
#include "apmib.h"

EXPORT_FUNCTION int stricmp(char *s1, char *s2)
{
	int ch1, ch2;

	do {
		ch1 = tolower(*s1++);
		ch2 = tolower(*s2++);
	} while (ch1 && (ch1 == ch2));

	return(ch1-ch2);
}

//dcshin
EXPORT_FUNCTION unsigned long mhtol(unsigned char *str, int str_len)
{
	int i;
	unsigned long ulret = 0;

	for (i=0; i<str_len; i++) {
		ulret = ( ulret<<8 ) | str[i];
	}

	return ulret;
}

char *trim_spaces(char *s)
{
	int len = strlen(s);
	/* trim trailing whitespace and double quotation */
	while (len > 0 && (isspace(s[len - 1]) || s[len - 1] == '"'))
		s[--len] = '\0';
	/* trim leading whitespace and double quotation */
	memmove(s, &s[strspn(s, " \n\r\t\v\"")], len);
	return s;
}

typedef void (*sighandler_t)(int);

char *flash_read(const char *keyword, char *value, int size)
{
	char cmd[128];
	char *ptr;
	FILE    *fp;
	sighandler_t save_quit, save_int, save_chld;
	char *sp;
	int len = 0;

	if (size ==0 || value == NULL)
		return NULL;

	value[0] = 0;
	sprintf(cmd, "flash get %s", keyword);
	save_quit = signal(SIGQUIT, SIG_IGN);
	save_int = signal(SIGINT, SIG_IGN);
	save_chld = signal(SIGCHLD, SIG_IGN);
	if ( (fp = popen(cmd, "r")) ) {
		if ( fgets(cmd, sizeof(cmd), fp) ) {
			ptr = strtok_r(cmd, "=", &sp);
			if ( ptr && (ptr=strtok_r(NULL, "=\r\n", &sp)) != NULL) {
				len = strlen(ptr);
				if ( ptr[0] == '\"' ) {
					ptr[len-1]='\0';
					sprintf(value, "%s", &ptr[1]);
				} else {
					sprintf(value, "%s", &ptr[0]);
				}
			}
		}
		pclose(fp);
	}
	signal(SIGQUIT, save_quit);
	signal(SIGINT, save_int);
	signal(SIGCHLD, save_chld);

	return ((value[0])? value: NULL);

}

static char *flash_vreadf(char *buf, int bufsize, const char *fmt, va_list va)
{
	char buffer[80 + 1];
	char *p, *q;
	int n, bsize;

	p = buffer;
	bsize = sizeof(buffer) - 1;
	for (q = NULL; p != NULL; q = p) {
		n = vsnprintf(p, bsize, fmt, va);
		if (n < bsize)
			break;
		bsize <<= 1;
		p = realloc(q, bsize + 1);
	}

	q = flash_read(p, buf, bufsize);
	if (p != buffer)
		free(p);
	return q;
}

char *flash_readf(char *buf, int bufsize, const char *fmt, ...)
{
	va_list va;
	char *p;

	va_start(va, fmt);
	p = flash_vreadf(buf, bufsize, fmt, va);
	va_end(va);
	return p;
}

int flash_readf_int(const char *fmt, ...)
{
	char buf[80];
	va_list va;

	buf[0] = '\0';
	va_start(va, fmt);
	flash_vreadf(buf, sizeof(buf), fmt, va);
	va_end(va);

	return atoi(buf);
}

void flash_set(const char *keyword, const char *value)
{
	char cmd[256];

	if (strlen(keyword) == 0)
		return;

	if (strlen(value))
		sprintf(cmd, "flash set %s \"%s\"", keyword, value);
	else
		sprintf(cmd, "flash set %s \"\"", keyword);

	system(cmd);
	return;

}

/////////////////////////////////////////////////////////////////////////////
int getMiscData(char *interface, struct _misc_data_ *pData)
{

	int skfd;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);

	strncpy(wrq.ifr_name, interface, IFNAMSIZ);
	/* Get wireless name */
	if ( ioctl(skfd, SIOCGIWNAME, &wrq) < 0) {
		printf("no wireless name....\n");
		/* If no wireless name : no wireless extensions */
		return -1;
	}
	wrq.u.data.pointer = (caddr_t)pData;
	wrq.u.data.length = sizeof(struct _misc_data_);

	strncpy(wrq.ifr_name, interface, IFNAMSIZ);

	if (ioctl(skfd, SIOCGMISCDATA, &wrq) < 0)
		return -1;
	close(skfd);
	return 0;
}

static int _is_hex(char c)
{
	return (((c >= '0') && (c <= '9')) ||
			((c >= 'A') && (c <= 'F')) ||
			((c >= 'a') && (c <= 'f')));
}
void string_to_hex(char *string, char *key, int len)
{
	unsigned char *p = (unsigned char *)string;
	int idx;
	int ii = 0;

	for (idx = 0; idx < len; idx++)
		ii += sprintf(&key[ii], "%02X", p[idx]);
	key[ii] = 0;
}

int hex_to_string(char *string, char *key, int len)
{
	char tmpBuf[4];
	int idx, ii=0;

	for (idx = 0; idx<len; idx+= 2) {
		tmpBuf[0] = string[idx];
		tmpBuf[1] = string[idx+1];
		tmpBuf[2] = 0;
		if (!_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;
		key[ii++] = (char)strtol(tmpBuf, NULL, 16);
	}

	return 1;
}

int simple_ether_atoe(char *strVal, unsigned char *MacAddr)
{
	int ii;
	int mac[6];

	if (strlen(strVal) == 12 && hex_to_string(strVal, MacAddr, 12))
		return 1;

	ii = sscanf(strVal, "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1], &mac[2],

			&mac[3], &mac[4], &mac[5]);
	if ( ii != 6)
		ii = sscanf(strVal, "%02x-%02x-%02x-%02x-%02x-%02x",&mac[0], &mac[1], &mac[2],

				&mac[3], &mac[4], &mac[5]);
	if (ii != 6)
		return 0;
	for (ii = 0; ii < 6; ii++)
		MacAddr[ii] = (unsigned char )(mac[ii] & 0xff);

	return 1;

}

int parse_line(char *line, char *argv[], int argvLen, const char *delim)
{
	char *q, *p = line;
	int		i, argc = 0;

	while ((q= strsep(&p, delim)) != NULL)  {
		trim_spaces(q);
		if (*q && (argc < argvLen))
			argv[argc++] = q;
	}
	for (i = argc; i < argvLen; i++)
		argv[i] = NULL;
	return argc;
}

int fread_line(const char *path, char *buf, int len)
{
	FILE *f;

	buf[0] = '\0';
	if (!path || !path[0] || !(f = fopen(path, "r")))
		return -1;
	fgets(buf, len, f);
	fclose(f);
	return 0;

}

int read_ip(const char *path, in_addr_t *addr, char *s)
{
	char buffer[64];

	if (fread_line(path, buffer, sizeof(buffer)))
		return 0;
	trim_spaces(buffer);
	if (!buffer[0])
		strcpy(buffer, "0.0.0.0");
	*addr = inet_addr(buffer);
	if (s)
		sprintf(s, "%u.%u.%u.%u", ((unsigned char *)addr)[0],
				((unsigned char *)addr)[1],
				((unsigned char *)addr)[2],
				((unsigned char *)addr)[3]);
	return 1;
}

int get_wan_ip(long *addr, char *buf)
{
	return read_ip("/var/wan_ip", (in_addr_t *)addr, buf);
}

