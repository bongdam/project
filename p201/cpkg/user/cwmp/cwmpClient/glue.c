#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include <bcmutils.h>
#include <libytool.h>
#include <ifport_counter.h>
#include "bcm_param_api.h"

int CONV_TO_RSSI(int percent)
{
	// formula:  dBm = (percent X 150)/135 - 100
	int dbm = ((percent * 10) / 9) - 100;
	return (dbm <= 0) ? dbm : 0;
}

int port_reset(int port, char *cfg)
{
	return strstr(cfg, "up_") ? yexecl(NULL, "sh -c \"carg=%s; phyconfig %d ${carg//_/ }\"", cfg, port) : -1;
}

int extract_info_from_url(char *url, struct url_info *info, unsigned short def_port)
{
	char *ptr = NULL;
	char *ptr_port = NULL;
	char *domain = NULL;
	int port = 0;

	if (!url || (url && (strlen(url) < 1)))
		return 0;

	if (!info)
		return 0;

	ptr = strstr(url, "://");	// ptr-> ://chgwacs.lgqps.com:443/chgw_configure
	if (ptr && strlen(ptr) > 3)
		strncpy(info->domain, ptr + 3, sizeof(info->domain) - 1);
	else
		strncpy(info->domain, url, sizeof(domain) - 1);

	domain = &(info->domain[0]);

	ptr = strchr(domain, ':');
	if (ptr) {
		if (strlen(ptr) > 1 && (*(ptr + 1) != '/')) {
			*ptr = 0;
			ptr_port = ptr + 1;
			ptr = strchr(ptr_port, '/');
			if (ptr) {
				if (strlen(ptr) > 1) {
					// ptr -> chgwacs.lgqps.com:40443/chgw_configure
					*ptr = 0;
					ptr += 1;
					snprintf(info->suburl, sizeof(info->suburl), "%s", ptr);
				} else {
					// ptr -> chgwacs.lgqps.com:40443/
					*ptr = 0;
				}
			} else {
				//chgwacs.lgqps.com:40443
			}

			port = atoi(ptr_port);
			if (port >= 1 && port <= 65535) {
				snprintf(info->port, sizeof(info->port), "%s", ptr_port);
			} else {
				// ptr -> chgwacs.lgqps.com:abcde/chgw_configure
				return 0;
			}
		} else {
			// ptr -> chgwacs.lgqps.com:/chgw_configure
			return 0;
		}
	} else {
		snprintf(info->port, sizeof(info->port), "%hu", def_port);
		ptr = strchr(domain, '/');
		if (ptr && strlen(ptr) > 1) {
			// ptr -> chgwacs.lgqps.com/chgw_configure
			*ptr = 0;
			ptr += 1;
			snprintf(info->suburl, sizeof(info->suburl), "%s", ptr);
		} else {
			// ptr -> chgwacs.lgqps.com
		}
	}

	return 1;
}

int ifport_counter(char *ifname, int eth_port, struct ifport_counter_t *c)
{
	memset(c, 0, sizeof(struct ifport_counter_t));
	return 0;
}

#define ATSERISKS_14TIMES "**************"

static int find_end(char *p, int max_index)
{
	int i;

	if (max_index < 0)
		return 0;

	for (i = max_index; i >= 0; i--) {
		if (p[i] != 0)
			return i;
	}

	return 0;
}

static int log_fgets(char *buf, int sz, FILE *fp)
{
	int len;

	memset(buf, 0, sz);
	if (fgets(buf, sz, fp) != NULL)
		len = find_end(buf, sz - 1);
	else
		len = -1;
	if (len >= sz)
		len = sz - 1;

	return len;
}

static int log_parse(char *tm_str, char **msg, char *buf, int buflen)
{
	char *p;
	int no_time_info = 0;

	if (buflen < 20)
		return -1;

// check if time string exist.
	if (buf[0] == '*') {
		if (memcmp(buf, ATSERISKS_14TIMES, 8) == 0)
			no_time_info = 1;
		else
			return -2;
	} else {
		if ((buf[4] != ' ') || (buf[7] != ' ') || (buf[10] != ' ') ||
		    (buf[13] != ':') || (buf[16] != ':') || (buf[19] != ' '))
			return -3;
	}

	p = &buf[20];

	while (*p) {
		if (*p != ' ')
			break;
		p++;
	}

	if (*p == 0)
		return -4;

	if (msg)
		*msg = p;

	if (no_time_info) {
		strcpy(tm_str, ATSERISKS_14TIMES);
	} else {
		int year, mon, day, hour, min, sec;

		sscanf(&buf[0], "%d %d %d %d:%d:%d", &year, &mon, &day, &hour, &min, &sec);
		sprintf(tm_str, "%04d%02d%02d%02d%02d%02d", year, mon, day, hour, min, sec);
	}

	return 1;
}

/*
RFC 3986 section 2.2 Reserved Characters (January 2005)
!	#	$	&	'	(	)	*	+	,	/	:	;	=	?	@	[	]
%21	%23	%24	%26	%27	%28	%29	%2A	%2B	%2C	%2F	%3A	%3B	%3D	%3F	%40	%5B	%5D
*/

//https://docs.oracle.com/javase/7/docs/api/java/net/URLDecoder.html

static const struct reserved {
	char chr;
	char val[3];
} reserved_set[] = {
	{'!', "%21"},
	{'\"', "%22"},
	{'#', "%23"},
	{'$', "%24"},
	{'%', "%25"},
	{'&', "%26"},
	{'\'', "%27"},
	{'(', "%28"},
	{')', "%29"},
	{'*', "%2A"},
	{'+', "%2B"},
	{',', "%2C"},
	{'/', "%2F"},
	{':', "%3A"},
	{';', "%3B"},
	{'<', "%3C"},
	{'=', "%3D"},
	{'>', "%3E"},
	{'?', "%3F"},
	{'@', "%40"},
	{'[', "%5B"},
	{'\\', "%5C"},
	{']', "%5D"},
	{'`', "%60"},
	{'{', "%7B"},
//	{'|', "%7C"},
	{'}', "%7D"},
	{'~', "%7E"}
};
#define RESERVED_SETSIZE (28 - 1)		// '|'

static int find_reserved_character(const void *ch1, const void *ch2)
{
	char ch = *(char *)ch1;
	struct reserved *resv = (struct reserved *)(ch2);

	if (ch > resv->chr)
		return 1;
	else if (ch == resv->chr)
		return 0;
	else
		return -1;
}

int percent_encode(char *str, char *encoded, int encodedsz)
{
	int i = 0;
	int j = 0;
	struct reserved *resv = NULL;

	if (!str)
		return 0;

	if (encodedsz < ((strlen(str) * 3) + 1))
		return 0;

	for (i = 0, j = 0; i < strlen(str) && j < encodedsz; i++) {
		resv = bsearch((void *)&str[i],
		               (void *)reserved_set,
		               RESERVED_SETSIZE,
		               4,
		               find_reserved_character);

		if (resv == NULL) {
			encoded[j++] = str[i];
		} else {
			encoded[j++] = resv->val[0];
			encoded[j++] = resv->val[1];
			encoded[j++] = resv->val[2];
		}
	}

	return j;
}

int get_diag_log(char *path, int http_encoding)
{
	FILE *pfp = NULL;
	FILE *fp = NULL;
	char buf[256];
	int len, wlen = 0;
	char tm_str[16];
	char *msg;
	int i = 0;

	if ((pfp = popen("dlogshow -a -u", "r")) == NULL)
		return 0;

	fp = fopen(path, "w");
	if (fp == NULL) {
		pclose(pfp);
		return 0;
	}

	while ((len = log_fgets(buf, sizeof(buf), pfp)) > 0) {
		if (len > 0 && log_parse(tm_str, &msg, buf, len) > 0) {
			if (http_encoding) {
				int j, k;
				char *cpstr;

				if (i++ > 0)
					wlen += fprintf(fp, "|");
				cpstr = strdup(msg);
				for (j = 0, k = 0; j < strlen(cpstr) && k < sizeof(buf); j++) {
					if (cpstr[j] == '+') {
						msg[k++] = '%';
						msg[k++] = '2';
						msg[k++] = 'B';
					} else if (cpstr[j] == '&') {
						msg[k++] = '%';
						msg[k++] = '2';
						msg[k++] = '6';
					} else if (cpstr[j] == '\n') { /* APACRTL-425 */
						continue;
					} else {
						msg[k++] = cpstr[j];
					}
				}
				msg[k] = 0;
				free(cpstr);
			}
			wlen += fprintf(fp, "%s %s", tm_str, msg);
		}
	}

	pclose(pfp);
	fclose(fp);

	return wlen;
}

int get_diag_log_tr069(char *path, int http_encoding)
{
	FILE *pfp = NULL;
	FILE *fp = NULL;
	char buf[256];
	char tmp[256];
	int len, wlen = 0;
	char tm_str[16];
	char *msg;
	int i = 0;
	char enc_msg[1024] = {0, };
	int enc_len = 0;

	if ((pfp = popen("dlogshow -a -u", "r")) == NULL)
		return 0;

	fp = fopen(path, "w");
	if (fp == NULL) {
		pclose(pfp);
		return 0;
	}

	while ((len = log_fgets(buf, sizeof(buf), pfp)) > 0) {
		if (len > 0 && log_parse(tm_str, &msg, buf, len) > 0) {
			if (http_encoding) {
				if (i++ > 0) {
					wlen += fprintf(fp, "|");
				}
				snprintf(tmp, sizeof(tmp), "%s", msg);
				if (strlen(tmp) && tmp[strlen(tmp) - 1] == '\n') {
					tmp[strlen(tmp) - 1] = 0;
				}
				memset(enc_msg, 0, sizeof(enc_msg));
				enc_len = percent_encode(tmp, enc_msg, sizeof(enc_msg));
				enc_msg[enc_len] = 0;
				wlen += fprintf(fp, "%s %s", tm_str, enc_msg);
			} else {
				wlen += fprintf(fp, "%s %s", tm_str, msg);
			}
		}
	}

	pclose(pfp);
	fclose(fp);

	return wlen;
}

char *lgu_default_val(int type, char *s, int slen)
{
	strlcpy(s, "admin", slen);
	return s;
}

int get_mcast_join_count(void)
{
	return 0;
}

void gsoap_ssl_set_protocol(int flags)
{
}

void soap_davo_set_cert_url(struct soap *soap, char *url)
{
}
