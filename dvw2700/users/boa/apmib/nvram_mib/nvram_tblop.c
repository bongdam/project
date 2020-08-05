#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>

#include "apmib.h"
#include "mibtbl.h"

#include <typedefs.h>
#include <bcmnvram.h>
#include "nvram_mib.h"
#include "libytool.h"

#define MAX_MIB_VALUE_LEN	1024
#define TBL_DELIM		",\r\n\t"
#define IPFMT			"%u.%u.%u.%u"

#define in_range(c, lo, up)  ((int)c >= lo && (int)c <= up)
#define isdigit(c)           in_range(c, '0', '9')
#define isxdigit(c)          (isdigit(c) || in_range(c, 'a', 'f') || in_range(c, 'A', 'F'))
#define islower(c)           in_range(c, 'a', 'z')

#define argumentize(str, args, least)					\
({                                                                      \
	int __n;                                                        \
	__n = ystrargs((str), (args), _countof(args), TBL_DELIM, 1);    \
	if (__n < least) {                                              \
		nm_errno = ENM_BADFMT;                                  \
		__n = 0;                                                \
	}                                                               \
	__n;                                                            \
})

static char *ystrunescape(char *dst, size_t n, const char *str)
{
	char *res = dst;
	unsigned char c;
	unsigned int val;
	int xx = 0;

	for (res = dst; (c = *str++) && n > 0; ) {
		if (xx > 0) {
			if (isdigit(c))
				val = (val << 4) + (int)(c - '0');
			else if (isxdigit(c))
				val = (val << 4) | (int)(c + 10 - (islower(c) ? 'a' : 'A'));
			else
				break;
			if (--xx > 0)
				continue;
			c = val;
		} else if (c == '%') {
			xx = 2;
			val = 0;
			continue;
		}
		*dst++ = c;
		n--;
	}

	if (c == 0 && n > 0)
		*dst = 0;

	return res;
}

static char *ystrescape(char *dst, size_t n, const char *str)
{
	const char *__xascii = "0123456789abcdef";
	char *res;
	unsigned char c;

	for (res = dst; (c = *str++) && n > 0; n--) {
		if (c != ',' && c != ' ' && c != '%')
			*dst++ = c;
		else if (n > 2) {
			*dst++ = '%';
			*dst++ = __xascii[(c >> 4) & 0xf];
			*dst++ = __xascii[c & 0xf];
			n -= 2;
		} else
			break;
	}

	if (c == 0 && n > 0)
		*dst = 0;

	return res;
}

static int tbl_num_increase(const struct mib *mib, const struct mib *nib)
{
	char name[80];
	int pos;

	ynvram_name(name, sizeof(name), nib->name, nib->section);
	pos = strtol(nvram_safe_get(name), NULL, 0);
	if (pos >= (int)mib->size) {
		nm_errno = ENM_FULL;
		return -1;
	}
	else if (pos < 0)
		pos = 0;
	/* [\w]+_TBL_NUM=\d+ */
	ynvram_put("%s=%d", name, pos + 1);
	return pos;
}

static int del_template(void *T,
			size_t L,
			const struct mib *M, const struct mib *N,
			int (*G)(void *, const char *, const struct mib *),
			void *D)
{
	char num_name[80], tbl_name[80];
	char *p;
	int i, ipos, len;

	ynvram_name(num_name, sizeof(num_name), N->name, N->section);
	ynvram_name(tbl_name, sizeof(tbl_name), M->name, M->section);
	len = strtol(nvram_safe_get(num_name), NULL, 0);
	if (len > (int)M->size)
		len = (int)M->size;

	/* if NULL, delete all. */
	if (T == NULL) {
		/* unset [\w]+_TBL[\d]+ */
		for (i = 0; i < len; i++)
			ynvram_unset("%s%d", tbl_name, i + 1);
		/* [\w]+_TBL_NUM=0 */
		ynvram_put("%s=0", num_name);
	} else {
		ipos = -1;
		for (i = 0; i < len; i++) {
			p = ynvram_get("%s%d", tbl_name, i + 1);
			memset(D, 0, L);
			if (p == NULL || G(D, p, NULL) == FALSE) {
				if (ipos < 0)
					ipos = i;
			} else if (!memcmp(D, T, L))
				break;
		}

		if (i < len) {
			if (ipos < 0)
				ipos = i;
			ynvram_unset("%s%d", tbl_name, i + 1);
			for (; i < (len - 1); i++) {
				p = ynvram_get("%s%d", tbl_name, i + 1 + 1);
				if (p == NULL || G(D, p, NULL) == FALSE)
					continue;
				ynvram_put("%s%d=%s", tbl_name, 1 + ipos++, p);
			}
			ynvram_unset("%s%d", tbl_name, i + 1);
			ynvram_put("%s=%d", num_name, ipos);
		}
	}

	return TRUE;
}

/*-----------------------------------------------------------------------------
   WLAC_ARRAY_T : MACFILTER_T
	unsigned char macAddr [6];
	unsigned char comment [21];
*/
static int
get_wlac_array_t(MACFILTER_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	2
#define OPT_ARGC	0
	char *args[MIN_ARGC + OPT_ARGC + 1];
	int status = FALSE;
	char *p = s ? strdup(s) : NULL;

	if (p != NULL) {
		if (argumentize(p, args, MIN_ARGC) == MIN_ARGC) {
			if (yxatoi(t->macAddr, args[0], sizeof(t->macAddr) << 1)) {
				ystrunescape((char *)t->comment, sizeof(t->comment), args[1]);
				status = TRUE;
			}
		}
		free(p);
	}
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_wlac_array_t(MACFILTER_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80], buf[sizeof(t->comment) << 2];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	/* [\w]+_TBL[\d]+=[[:xdigit:]]{12},\s*[\w]* */
	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=%02x%02x%02x%02x%02x%02x,%s", name, pos + 1,
		t->macAddr[0], t->macAddr[1], t->macAddr[2],
		t->macAddr[3], t->macAddr[4], t->macAddr[5],
		ystrescape(buf, sizeof(buf), (char *)t->comment));

	return TRUE;
}

static int
del_wlac_array_t(MACFILTER_T *t, const struct mib *mib, const struct mib *nib)
{
	MACFILTER_T flt;
	return del_template(t, sizeof(flt), mib, nib, (void *)get_wlac_array_t, (void *)&flt);
}

/*-----------------------------------------------------------------------------
   DHCPRSVDIP_ARRY_T : DHCPRSVDIP_T
#ifdef _PRMT_X_TELEFONICA_ES_DHCPOPTION_
	unsigned char dhcpRsvdIpEntryEnabled;
#endif
	unsigned char ipAddr [4];
	unsigned char macAddr [6];
	unsigned char hostName [32];
	unsigned int InstanceNum ;	// unused
 */
static int
get_dhcprsvdip_arry_t(DHCPRSVDIP_T *t, const char *s, const struct mib *mib)
{
#ifdef _PRMT_X_TELEFONICA_ES_DHCPOPTION_
# define MIN_ARGC	3
#else
# define MIN_ARGC	2
#endif
#define OPT_ARGC	1
	char *args[MIN_ARGC + OPT_ARGC + 1], **argp;
	char *p = s ? strdup(s) : NULL;
	int status = FALSE;

	if (p == NULL)
		return FALSE;
	argp = args;
	if (argumentize(p, args, MIN_ARGC)) {
		do {
#ifdef _PRMT_X_TELEFONICA_ES_DHCPOPTION_
			t->dhcpRsvdIpEntryEnabled = strtol(*argp++, NULL, 0);
#endif
			if (!yxatoi(t->macAddr, *argp++, sizeof(t->macAddr) << 1))
				break;
			if (!inet_aton(*argp++, (struct in_addr *)&t->ipAddr[0]))
				break;
			ystrunescape((char *)t->hostName, sizeof(t->hostName), *argp ? : "");
			status = TRUE;
		} while (0);
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_dhcprsvdip_arry_t(DHCPRSVDIP_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80], buf[sizeof(t->hostName) << 2];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=%02x%02x%02x%02x%02x%02x," IPFMT ",%s", name, pos + 1,
		t->macAddr[0], t->macAddr[1], t->macAddr[2],
		t->macAddr[3], t->macAddr[4], t->macAddr[5],
		t->ipAddr[0], t->ipAddr[1], t->ipAddr[2], t->ipAddr[3],
		ystrescape(buf, sizeof(buf), (char *)t->hostName));

	return TRUE;
}

static int
del_dhcprsvdip_arry_t(DHCPRSVDIP_T *t, const struct mib *mib, const struct mib *nib)
{
	DHCPRSVDIP_T slease;
	return del_template(t, sizeof(slease), mib, nib, (void *)get_dhcprsvdip_arry_t, (void *)&slease);
}

#ifdef HOME_GATEWAY
/*-----------------------------------------------------------------------------
  PORTFW_ARRAY_T : PORTFW_T
	unsigned char ipAddr [4];
	unsigned short fromPort ;
	unsigned short toPort ;
	unsigned char protoType ;
	unsigned short svrport ;	// unused
	unsigned char svrName [21];	// unused
	unsigned int InstanceNum ;
	unsigned int WANIfIndex ;	// unused
	unsigned char comment [21];

	unsigned short externelFromPort ;
	unsigned short externelToPort ;
	unsigned char rmtipAddr [4];
	unsigned char enabled ;
 */
static int
get_portfw_array_t(PORTFW_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	8
#define OPT_ARGC	1
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int status = FALSE;

	if (p == NULL)
		return FALSE;
	if (argumentize(p, args, MIN_ARGC)) {
		if (inet_aton(args[0], (struct in_addr *)&t->ipAddr[0])) {
			t->fromPort = strtoul(args[1], NULL, 0);
			t->toPort = strtoul(args[2], NULL, 0);
			t->protoType = strtoul(args[3], NULL, 0);
			t->externelFromPort = strtoul(args[4], NULL, 0);
			t->externelToPort = strtoul(args[5], NULL, 0);
			inet_aton(args[6], (struct in_addr *)&t->rmtipAddr[0]);
			t->enabled = strtoul(args[7], NULL, 0);
			ystrunescape((char *)t->comment, sizeof(t->comment), (args[8]) ? : "");
			status = TRUE;
		}
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_portfw_array_t(PORTFW_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80], buf[sizeof(t->comment) << 2];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=" IPFMT ",%u,%u,%u,%u,%u," IPFMT ",%u,%s", name, pos + 1,
		t->ipAddr[0], t->ipAddr[1], t->ipAddr[2], t->ipAddr[3],
		t->fromPort,
		t->toPort,
		t->protoType,
		t->externelFromPort, t->externelToPort,
		t->rmtipAddr[0], t->rmtipAddr[1], t->rmtipAddr[2], t->rmtipAddr[3],
		t->enabled,
		ystrescape(buf, sizeof(buf), (char *)t->comment));

	return TRUE;
}

static int
del_portfw_array_t(PORTFW_T *t, const struct mib *mib, const struct mib *nib)
{
	PORTFW_T pfw;
	return del_template(t, sizeof(pfw), mib, nib, (void *)get_portfw_array_t, (void *)&pfw);
}

/*-----------------------------------------------------------------------------
   IPFILTER_ARRAY_T : IPFILTER_T
	unsigned char ipAddr [4];
	unsigned char protoType ;
	unsigned char comment [21];
#ifdef CONFIG_IPV6
	unsigned char ip6Addr [48];
	unsigned char ipVer;
#endif
 */
static int
get_ipfilter_array_t(IPFILTER_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	2
#ifdef CONFIG_IPV6
# define OPT_ARGC	3
#else
# define OPT_ARGC	1
#endif
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int status = FALSE;

	if (p == NULL)
		return FALSE;
	if (argumentize(p, args, MIN_ARGC)) {
		if (inet_aton(args[0], (struct in_addr *)&t->ipAddr[0])) {
			t->protoType = strtoul(args[1], NULL, 0);
			ystrunescape((char *)t->comment, sizeof(t->comment), (args[2]) ? : "");
#ifdef CONFIG_IPV6
			ystrncpy((char *)t->ip6Addr, args[3] ? : "", sizeof(t->ip6Addr));
			t->ipVer = strtol(args[4] ? : "", NULL, 0);
#endif
			status = TRUE;
		}
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_ipfilter_array_t(IPFILTER_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80], buf[sizeof(t->comment) << 2];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=" IPFMT ",%u,%s"
#ifdef CONFIG_IPV6
		",%s,%u"
#endif
		, name, pos + 1,
		t->ipAddr[0], t->ipAddr[1], t->ipAddr[2], t->ipAddr[3],
		t->protoType, ystrescape(buf, sizeof(buf), (char *)t->comment)
#ifdef CONFIG_IPV6
		, t->ip6Addr, t->ipVer
#endif
		);

	return TRUE;
}

static int
del_ipfilter_array_t(IPFILTER_T *t, const struct mib *mib, const struct mib *nib)
{
	IPFILTER_T ipflt;
	return del_template(t, sizeof(ipflt), mib, nib, (void *)get_ipfilter_array_t, (void *)&ipflt);
}

/*-----------------------------------------------------------------------------
   PORTFILTER_ARRAY_T : PORTFILTER_T
	unsigned short fromPort ;
	unsigned short toPort ;
	unsigned char protoType ;
	unsigned char comment [21];
	unsigned char ipVer ;		// unused
 */
static int
get_portfilter_array_t(PORTFILTER_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	3
#define OPT_ARGC	1
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int status = FALSE;

	if (p == NULL)
		return FALSE;
	if (argumentize(p, args, MIN_ARGC)) {
		t->fromPort = strtoul(args[0], NULL, 0);
		t->toPort = strtoul(args[1], NULL, 0);
		t->protoType = strtoul(args[2], NULL, 0);
		ystrunescape((char *)t->comment, sizeof(t->comment), (args[3]) ? : "");
		status = TRUE;
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_portfilter_array_t(PORTFILTER_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80], buf[sizeof(t->comment) << 2];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=%u,%u,%u,%s", name, pos + 1,
		t->fromPort, t->toPort, t->protoType,
		ystrescape(buf, sizeof(buf), (char *)t->comment));

	return TRUE;
}

static int
del_portfilter_array_t(PORTFILTER_T *t, const struct mib *mib, const struct mib *nib)
{
	PORTFILTER_T pflt;
	return del_template(t, sizeof(pflt), mib, nib, (void *)get_portfilter_array_t, (void *)&pflt);
}

/*-----------------------------------------------------------------------------
   MACFILTER_ARRAY_T : MACFILTER_T
	unsigned char macAddr [6];
	unsigned char comment [21];
 */
#define get_macfilter_array_t	get_wlac_array_t
#define add_macfilter_array_t	add_wlac_array_t
#define del_macfilter_array_t	del_wlac_array_t

/*-----------------------------------------------------------------------------
   URLFILTER_ARRAY_T : URLFILTER_T
	unsigned char urlAddr [31];
	unsigned char ruleMode ;
#ifdef URL_FILTER_USER_MODE_SUPPORT
	unsigned char urlMode;
	unsigned char ipAddr [4];
	unsigned char macAddr [6];
#endif
 */
#ifdef URL_FILTER_USER_MODE_SUPPORT
# error Not Implemented in URL_FILTER_USER_MODE_SUPPORT defined!
#endif
static int urlcopy_without_scheme(char *dst, int len, const char *url)
{
	regex_t reg;
	regmatch_t match[6], *pmatch = NULL;
	int i;

	if (regcomp(&reg, "^([a-z][a-z0-9+\\-\\.]*://)?(.*)",
			REG_EXTENDED | REG_NEWLINE))
		return -1;
	if (!regexec(&reg, url, _countof(match), match, 0)) {
		for (i = 0; i < _countof(match); i++) {
			if (match[i].rm_so < 0)
				break;
			pmatch = &match[i];
		}
	}
	regfree(&reg);

	if (pmatch && (i = (pmatch->rm_eo - pmatch->rm_so)) > 0) {
		memset(dst, 0, len);
		snprintf(dst, len, "%.*s", i, &url[pmatch->rm_so]);
		return 0;
	}

	return -1;
}

static int
get_urlfilter_array_t(URLFILTER_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	1
#define OPT_ARGC	1
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int status = FALSE;

	if (p == NULL)
		return FALSE;
	if (argumentize(p, args, MIN_ARGC)) {
		if (!urlcopy_without_scheme((char *)t->urlAddr, sizeof(t->urlAddr), args[0])) {
			t->ruleMode = strtol(args[1] ? args[1] : "", NULL, 0);
			status = TRUE;
		} else
			nm_errno = ENM_INVAL;
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_urlfilter_array_t(URLFILTER_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80], url[128];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;
	if (urlcopy_without_scheme(url, sizeof(url), (const char *)t->urlAddr)) {
		nm_errno = ENM_INVAL;
		return FALSE;
	}
	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=%s,%u", name, pos + 1, url, t->ruleMode);

	return TRUE;
}

static int
del_urlfilter_array_t(URLFILTER_T *t, const struct mib *mib, const struct mib *nib)
{
	URLFILTER_T url;
	return del_template(t, sizeof(url), mib, nib, (void *)get_urlfilter_array_t, (void *)&url);
}

/*-----------------------------------------------------------------------------
   TRIGGERPORT_ARRAY_T : TRIGGERPORT_T
	unsigned short tri_fromPort ;
	unsigned short tri_toPort ;
	unsigned char tri_protoType ;
	unsigned short inc_fromPort ;
	unsigned short inc_toPort ;
	unsigned char inc_protoType ;
	unsigned char comment [21];
 */
static int
get_triggerport_array_t(TRIGGERPORT_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	6
#define OPT_ARGC	1
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int status = FALSE;

	if (p == NULL)
		return FALSE;
	if (argumentize(p, args, MIN_ARGC)) {
		t->tri_fromPort = strtoul(args[0], NULL, 0);
		t->tri_toPort = strtoul(args[1], NULL, 0);
		t->tri_protoType = strtoul(args[2], NULL, 0);
		t->inc_fromPort = strtoul(args[3], NULL, 0);
		t->inc_toPort = strtoul(args[4], NULL, 0);
		t->inc_protoType = strtoul(args[5], NULL, 0);
		ystrunescape((char *)t->comment, sizeof(t->comment), (args[6]) ? : "");
		status = TRUE;
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_triggerport_array_t(TRIGGERPORT_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80], buf[sizeof(t->comment) << 2];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=%u,%u,%u,%u,%u,%u,%s", name, pos + 1,
		t->tri_fromPort, t->tri_toPort, t->tri_protoType,
		t->inc_fromPort, t->inc_toPort, t->inc_protoType,
		ystrescape(buf, sizeof(buf), (char *)t->comment));

	return TRUE;
}

static int
del_triggerport_array_t(TRIGGERPORT_T *t, const struct mib *mib, const struct mib *nib)
{
	TRIGGERPORT_T trgprt;
	return del_template(t, sizeof(trgprt), mib, nib, (void *)get_triggerport_array_t, (void *)&trgprt);
}

#ifdef ROUTE_SUPPORT
/*-----------------------------------------------------------------------------
   STATICROUTE_ARRAY_T : STATICROUTE_T
	unsigned char dstAddr [4];
	unsigned char netmask [4];
	unsigned char gateway [4];
	unsigned char interface ;
	int metric ;
	unsigned char Enable ;		// unused
	unsigned char Type ;		// unused
	unsigned char SourceIP [4];	// unused
	unsigned char SourceMask [4];	// unused
	unsigned int ifIndex ;		// unused
	unsigned int InstanceNum ;	// unused
	unsigned char Flags ;		// unused
 */
static int
get_staticroute_array_t(STATICROUTE_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	3
#define OPT_ARGC	2
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int status = FALSE;

	if (p == NULL)
		return FALSE;
	if (argumentize(p, args, MIN_ARGC)) {
		do {
			if (!inet_aton(args[0], (struct in_addr *)&t->dstAddr[0]))
				break;
			if (!inet_aton(args[1], (struct in_addr *)&t->netmask[0]))
				break;
			if (!inet_aton(args[2], (struct in_addr *)&t->gateway[0]))
				break;
			t->interface = strtol(args[3] ? : "0", NULL, 0);
			t->metric = strtol(args[4] ? : "0", NULL, 0);
			status = TRUE;
		} while (0);
		if (status != TRUE)
			nm_errno = ENM_INVAL;
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_staticroute_array_t(STATICROUTE_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=" IPFMT "," IPFMT "," IPFMT ",%u,%d", name, pos + 1,
		t->dstAddr[0], t->dstAddr[1], t->dstAddr[2], t->dstAddr[3],
		t->netmask[0], t->netmask[1], t->netmask[2], t->netmask[3],
		t->gateway[0], t->gateway[1], t->gateway[2], t->gateway[3],
		t->interface, t->metric);

	return TRUE;
}

static int
del_staticroute_array_t(STATICROUTE_T *t, const struct mib *mib, const struct mib *nib)
{
	STATICROUTE_T srt;
	return del_template(t, sizeof(srt), mib, nib, (void *)get_staticroute_array_t, (void *)&srt);
}
#endif	/* ROUTE_SUPPORT */
#ifdef VPN_SUPPORT
# error Not Implemented in VPN_SUPPORT defined!
#endif
#endif	/* HOME_GATEWAY */
/*-----------------------------------------------------------------------------
   WDS_ARRAY_T : WDS_T
	unsigned char macAddr [6];
	unsigned int fixedTxRate ;
	unsigned char comment [21];
 */
static int
get_wds_array_t(WDS_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	2
#define OPT_ARGC	1
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int status = FALSE;

	if (p == NULL)
		return FALSE;
	if (argumentize(p, args, MIN_ARGC)) {
		if (yxatoi(t->macAddr, args[0], sizeof(t->macAddr) << 1)) {
			t->fixedTxRate = strtoul(args[1], NULL, 0);
			ystrunescape((char *)t->comment, sizeof(t->comment), (args[2]) ? : "");
			status = TRUE;
		}
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_wds_array_t(WDS_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80], buf[sizeof(t->comment) << 2];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=%02x%02x%02x%02x%02x%02x,%u,%s", name, pos + 1,
		t->macAddr[0], t->macAddr[1], t->macAddr[2],
		t->macAddr[3], t->macAddr[4], t->macAddr[5],
		t->fixedTxRate, ystrescape(buf, sizeof(buf), (char *)t->comment));

	return TRUE;
}

static int
del_wds_array_t(WDS_T *t, const struct mib *mib, const struct mib *nib)
{
	WDS_T wds;
	return del_template(t, sizeof(wds), mib, nib, (void *)get_wds_array_t, (void *)&wds);
}

#ifdef QOS_BY_BANDWIDTH
/*-----------------------------------------------------------------------------
   QOS_ARRAY_T : IPQOS_T
	unsigned char entry_name [15 +1];
	unsigned char enabled ;
	unsigned char mac [6];
	unsigned char mode ;
	unsigned char local_ip_start [4];
	unsigned char local_ip_end [4];
	unsigned long bandwidth ;
	unsigned long bandwidth_downlink ;
	unsigned char l7_protocol [64+1];
	unsigned char ip6_src [40];
#if defined(ADVANCED_IPQOS)
	unsigned char dst_mac [6];
	unsigned char protocol ;
	unsigned short local_port_start ;
	unsigned short local_port_end ;
	unsigned char remote_ip_start [4];
	unsigned char remote_ip_end [4];
	unsigned short remote_port_start ;
	unsigned short remote_port_end ;

	unsigned char dscp ;

	unsigned char vlan_pri ;

	unsigned char policy ;
	unsigned char priority ;
	unsigned long weight ;
	unsigned char phyport ;

	unsigned char remark_dscp ;

	unsigned char remark_vlan_pri ;
#endif
 */
static int
get_qos_array_t(IPQOS_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	8
#ifdef ADVANCED_IPQOS
#undef MIN_ARGC
#define MIN_ARGC	24
#endif
#define OPT_ARGC	0
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int status = FALSE;

	if (p == NULL)
		return FALSE;
	if (argumentize(p, args, MIN_ARGC)) {
		do {
			t->enabled = strtol(args[0], NULL, 0);
			if (!yxatoi(t->mac, args[1], sizeof(t->mac) << 1))
				break;
			t->mode = strtol(args[2], NULL, 0);
			if (!inet_aton(args[3], (struct in_addr *)&t->local_ip_start[0]) ||
			    !inet_aton(args[4], (struct in_addr *)&t->local_ip_end[0]))
				break;
			t->bandwidth = strtol(args[5], NULL, 0);
			t->bandwidth_downlink = strtol(args[6], NULL, 0);
			ystrunescape((char *)t->entry_name, sizeof(t->entry_name), args[7]);
#ifdef ADVANCED_IPQOS
			if (!yxatoi(t->dst_mac, args[8], sizeof(t->dst_mac) << 1))
				break;
			t->protocol = strtol(args[9], NULL, 0);
			t->local_port_start = strtol(args[10], NULL, 0);
			t->local_port_end = strtol(args[11], NULL, 0);
			if (!inet_aton(args[12], (struct in_addr *)&t->remote_ip_start[0]) ||
			    !inet_aton(args[13], (struct in_addr *)&t->remote_ip_end[0]))
				break;
			t->remote_port_start = strtol(args[14], NULL, 0);
			t->remote_port_end = strtol(args[15], NULL, 0);
			t->dscp = strtol(args[16], NULL, 0);;
			t->vlan_pri = strtol(args[17], NULL, 0);;
			t->policy = strtol(args[18], NULL, 0);;
			t->priority = strtol(args[19], NULL, 0);;
			t->weight = strtol(args[20], NULL, 0);;
			t->phyport = strtol(args[21], NULL, 0);;
			t->remark_dscp = strtol(args[22], NULL, 0);;
			t->remark_vlan_pri = strtol(args[23], NULL, 0);;
#endif
			status = TRUE;
		} while (0);
		if (status != TRUE)
			nm_errno = ENM_INVAL;
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_qos_array_t(IPQOS_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80], buf[sizeof(t->entry_name) << 2];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=%d,%02x%02x%02x%02x%02x%02x,%d," IPFMT "," IPFMT ",%u,%u,%s"
#ifdef ADVANCED_IPQOS
		",%02x%02x%02x%02x%02x%02x,%u,%u,%u," IPFMT "," IPFMT ",%u"
		",%u,%u,%u,%u,%u,%u,%u,%u,%u"
#endif
		,
		name, pos + 1,
		t->enabled,
		t->mac[0], t->mac[1], t->mac[2], t->mac[3], t->mac[4], t->mac[5],
		t->mode,
		t->local_ip_start[0], t->local_ip_start[1], t->local_ip_start[2], t->local_ip_start[3],
		t->local_ip_end[0], t->local_ip_end[1], t->local_ip_end[2], t->local_ip_end[3],
		t->bandwidth, t->bandwidth_downlink, ystrescape(buf, sizeof(buf), (char *)t->entry_name)
#ifdef ADVANCED_IPQOS
		, t->dst_mac[0], t->dst_mac[1], t->dst_mac[2],
		t->dst_mac[3], t->dst_mac[4], t->dst_mac[5],
		t->protocol, t->local_port_start, t->local_port_end,
		t->remote_ip_start[0], t->remote_ip_start[1], t->remote_ip_start[2], t->remote_ip_start[3],
		t->remote_ip_end[0], t->remote_ip_end[1], t->remote_ip_end[2], t->remote_ip_end[3],
		t->remote_port_start, t->remote_port_end,
		t->dscp, t->vlan_pri, t->policy,
		t->priority, t->weight, t->phyport, t->remark_dscp, t->remark_vlan_pri
#endif
		);

	return TRUE;
}

static int
del_qos_array_t(IPQOS_T *t, const struct mib *mib, const struct mib *nib)
{
	IPQOS_T qos;
	return del_template(t, sizeof(qos), mib, nib, (void *)get_qos_array_t, (void *)&qos);
}
#elif defined(GW_QOS_ENGINE)
# error Not Implemented in GW_QOS_ENGINE defined!
#endif

/*-----------------------------------------------------------------------------
   MESH_ACL_ARRAY_T : MACFILTER_T
	unsigned char macAddr [6];
	unsigned char comment [21];
 */
#define get_mesh_acl_array_t	get_wlac_array_t
#define add_mesh_acl_array_t	add_wlac_array_t
#define del_mesh_acl_array_t	del_wlac_array_t

/*-----------------------------------------------------------------------------
   SCHEDULE_ARRAY_T : SCHEDULE_T
	unsigned char text [20];
	unsigned short eco ;		// enabled 0|1
	unsigned short fTime ;		// From 0 ~ 1440 (24h*60m)
	unsigned short tTime ;		// To 0 ~ 1440(24h*60m)
	unsigned short day ;		// Day 0 ~ 7
 */
static int
get_schedule_array_t(SCHEDULE_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	4
#ifndef NEW_SCHEDULE_SUPPORT
# define OPT_ARGC	0
#else
# define OPT_ARGC	1
#endif
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int status = FALSE;

	if (p == NULL)
		return FALSE;
	if (argumentize(p, args, MIN_ARGC)) {
		do {
			t->eco = strtol(args[0], NULL, 0);
			if (t->eco > 1)
				break;
			t->day = strtol(args[1], NULL, 0);
			if (t->day > 7)
				break;
			t->fTime = strtol(args[2], NULL, 0);
			if (t->fTime >= 1440)
				break;
			t->tTime = strtol(args[3], NULL, 0);
			if (t->tTime >= 1440)
				break;
#ifndef NEW_SCHEDULE_SUPPORT
			ystrunescape((char *)t->text, sizeof(t->text), args[4] ? : "");
#endif
			status = TRUE;
		} while (0);
		if (status != TRUE)
			nm_errno = ENM_INVAL;
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_schedule_array_t(SCHEDULE_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80];
#ifndef NEW_SCHEDULE_SUPPORT
	char buf[sizeof(t->text) << 2];
#endif
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=%u,%u,%u,%u"
#ifndef NEW_SCHEDULE_SUPPORT
		",%s"
#endif
		, name, pos + 1,
		t->eco, t->day, t->fTime, t->tTime
#ifndef NEW_SCHEDULE_SUPPORT
		, ystrescape(buf, sizeof(buf), (char *)t->text)
#endif
		);

	return TRUE;
}

static int
del_schedule_array_t(SCHEDULE_T *t, const struct mib *mib, const struct mib *nib)
{
	SCHEDULE_T sched;
	return del_template(t, sizeof(sched), mib, nib, (void *)get_schedule_array_t, (void *)&sched);
}

#ifdef VLAN_CONFIG_SUPPORTED
/*-----------------------------------------------------------------------------
   VLANCONFIG_ARRAY_T : VLAN_CONFIG_T
	unsigned char enabled ;
	unsigned char netIface [16];
	unsigned char tagged ;
	unsigned char priority ;
	unsigned char cfi ;
	unsigned short vlanId ;
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) || defined(CONFIG_RTL_HW_VLAN_SUPPORT)
	unsigned char forwarding_rule ;
#endif
 */
static int
get_vlanconfig_array_t(VLAN_CONFIG_T *t, const char *s, const struct mib *mib)
{
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) || defined(CONFIG_RTL_HW_VLAN_SUPPORT)
# define MIN_ARGC	7
#else
# define MIN_ARGC	6
#endif
#define OPT_ARGC	0
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int argc, status = FALSE;

	if (p == NULL)
		return FALSE;
	if ((argc = argumentize(p, args, MIN_ARGC))) {
		ystrunescape((char *)t->netIface, sizeof(t->netIface), args[0]);
		t->enabled = strtol(args[1], NULL, 0);
		t->tagged = strtol(args[2], NULL, 0);
		t->priority = strtol(args[3], NULL, 0);
		t->cfi = strtol(args[4], NULL, 0);
		t->vlanId = strtol(args[5], NULL, 0);
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) || defined(CONFIG_RTL_HW_VLAN_SUPPORT)
		t->forwarding_rule = strtol(args[argc - 1], NULL, 0);
#endif
		status = TRUE;
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_vlanconfig_array_t(VLAN_CONFIG_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80], buf[sizeof(t->netIface) << 2];
	int pos;

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ynvram_put("%s%d=%s,%u,%u,%u,%u,%u"
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) || defined(CONFIG_RTL_HW_VLAN_SUPPORT)
		",%u"
#endif
		, name, pos + 1,
		ystrescape(buf, sizeof(buf), (char *)t->netIface),
		t->enabled,
		t->tagged,
		t->priority,
		t->cfi,
		t->vlanId
#if defined(CONFIG_RTK_VLAN_NEW_FEATURE) || defined(CONFIG_RTL_HW_VLAN_SUPPORT)
		, t->forwarding_rule
#endif
		);

	return TRUE;
}

static int
del_vlanconfig_array_t(VLAN_CONFIG_T *t, const struct mib *mib, const struct mib *nib)
{
	VLAN_CONFIG_T vconf;
	return del_template(t, sizeof(vconf), mib, nib, (void *)get_vlanconfig_array_t, (void *)&vconf);
}
#endif

#ifdef WLAN_PROFILE
/*-----------------------------------------------------------------------------
   PROFILE_ARRAY_T : WLAN_PROFILE_T
	unsigned char ssid [33];
	unsigned char encryption ;
	unsigned char auth ;
	unsigned char wpa_cipher ;
	unsigned char wpaPSK [64 +1];
	unsigned char wep_default_key ;
	unsigned char wepKey1 [13*2+1];
	unsigned char wepKey2 [13*2+1];
	unsigned char wepKey3 [13*2+1];
	unsigned char wepKey4 [13*2+1];
	unsigned char wepKeyType ;
	unsigned char wpaPSKFormat ;

	-- one of two possible
	ssid,encryption,auth,wep_default_key,wepKey1,..,wepKey4
	ssid,encryption,auth,wpa_cipher,wpaPSK
 */
static int
get_profile_array_t(WLAN_PROFILE_T *t, const char *s, const struct mib *mib)
{
#define MIN_ARGC	3
#define OPT_ARGC	5
	char *args[MIN_ARGC + OPT_ARGC + 1];
	char *p = s ? strdup(s) : NULL;
	int keylen, argc, status = FALSE;

	if (p == NULL)
		return FALSE;
	memset(t, 0, sizeof(*t));
	if ((argc = argumentize(p, args, MIN_ARGC))) {
		ystrunescape((char *)t->ssid, sizeof(t->ssid), args[0]);
		t->encryption = strtol(args[1], NULL, 0);
		t->auth = strtol(args[2], NULL, 0);
		switch (t->encryption) {
		case 0:
			status = TRUE;
			break;
		case 1:
		case 2:
			if (argc != (MIN_ARGC + OPT_ARGC))
				break;
			t->wep_default_key = strtol(args[3], NULL, 0);
			if (t->wep_default_key > 4) {
				nm_errno = ENM_INVAL;
				break;
			}
			keylen = (t->encryption == 1) ? 10 : 26;
			if (yxatoi(t->wepKey1, args[4], keylen) != TRUE ||
			    yxatoi(t->wepKey2, args[5], keylen) != TRUE ||
			    yxatoi(t->wepKey3, args[6], keylen) != TRUE ||
			    yxatoi(t->wepKey4, args[7], keylen) != TRUE)
				break;
			status = TRUE;
			break;
		case 3:
		case 4:
			if (argc != 5)
				break;
			t->wpa_cipher = strtol(args[3], NULL, 0);
			ystrunescape((char *)t->wpaPSK, sizeof(t->wpaPSK), args[4]);
			status = TRUE;
			break;
		default:
			break;
		}
	}
	free(p);
#undef MIN_ARGC
#undef OPT_ARGC
	return status;
}

static int
add_profile_array_t(WLAN_PROFILE_T *t, const struct mib *mib, const struct mib *nib)
{
	char name[80];
	char buf[4][32];
	char ssid[sizeof(t->ssid) << 2];
	int keylen, pos;

	if (t->encryption > 4) {
		nm_errno = ENM_INVAL;
		return FALSE;
	}

	if ((pos = tbl_num_increase(mib, nib)) < 0)
		return FALSE;

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	ystrescape(ssid, sizeof(ssid), (char *)t->ssid);
	switch (t->encryption) {
	case 0:
		ynvram_put("%s%d=%s,%u,%u", name, pos + 1,
			ssid, t->encryption, t->auth);
		break;
	case 1:
	case 2:
		keylen = (t->encryption == 1) ? 5 : 13;
		ynvram_put("%s%d=%s,%u,%u,%u,%s,%s,%s,%s", name, pos + 1,
			ssid, t->encryption, t->auth,
			t->wep_default_key,
			yitoxa(buf[0], t->wepKey1, keylen),
			yitoxa(buf[1], t->wepKey2, keylen),
			yitoxa(buf[2], t->wepKey3, keylen),
			yitoxa(buf[3], t->wepKey4, keylen));
		break;
	case 3:
	case 4:
		ynvram_put("%s%d=%s,%u,%u,%u,%s", name, pos + 1,
			ssid, t->encryption, t->auth,
			t->wpa_cipher, t->wpaPSK);
		break;
	default:
		break;
	}

	return TRUE;
}

static int
del_profile_array_t(WLAN_PROFILE_T *t, const struct mib *mib, const struct mib *nib)
{
	WLAN_PROFILE_T profile;
	return del_template(t, sizeof(profile), mib, nib, (void *)get_profile_array_t, (void *)&profile);
}
#endif	/* WLAN_PROFILE */

const static struct mib_tbl_operation tops[] = {
	{ WLAC_ARRAY_T,		(void *)get_wlac_array_t,	(void *)add_wlac_array_t,		(void *)del_wlac_array_t },
	{ DHCPRSVDIP_ARRY_T,	(void *)get_dhcprsvdip_arry_t,	(void *)add_dhcprsvdip_arry_t,		(void *)del_dhcprsvdip_arry_t },
#ifdef HOME_GATEWAY
	{ PORTFW_ARRAY_T,	(void *)get_portfw_array_t,	(void *)add_portfw_array_t,		(void *)del_portfw_array_t },
	{ IPFILTER_ARRAY_T,	(void *)get_ipfilter_array_t,	(void *)add_ipfilter_array_t,		(void *)del_ipfilter_array_t },
	{ PORTFILTER_ARRAY_T,	(void *)get_portfilter_array_t,	(void *)add_portfilter_array_t,		(void *)del_portfilter_array_t },
	{ MACFILTER_ARRAY_T,	(void *)get_macfilter_array_t,	(void *)add_macfilter_array_t,		(void *)del_macfilter_array_t },
	{ URLFILTER_ARRAY_T,	(void *)get_urlfilter_array_t,	(void *)add_urlfilter_array_t,		(void *)del_urlfilter_array_t },
	{ TRIGGERPORT_ARRAY_T,	(void *)get_triggerport_array_t, (void *)add_triggerport_array_t,	(void *)del_triggerport_array_t },
#ifdef ROUTE_SUPPORT
	{ STATICROUTE_ARRAY_T,	(void *)get_staticroute_array_t, (void *)add_staticroute_array_t,	(void *)del_staticroute_array_t },
#endif	/* ROUTE_SUPPORT */
#endif	/* HOME_GATEWAY */
	{ WDS_ARRAY_T,		(void *)get_wds_array_t,	(void *)add_wds_array_t,		(void *)del_wds_array_t },
#if defined(GW_QOS_ENGINE) || defined(QOS_BY_BANDWIDTH)
	{ QOS_ARRAY_T,		(void *)get_qos_array_t,	(void *)add_qos_array_t,		(void *)del_qos_array_t },
#endif
	{ MESH_ACL_ARRAY_T,	(void *)get_mesh_acl_array_t,	(void *)add_mesh_acl_array_t,		(void *)del_mesh_acl_array_t },
	{ SCHEDULE_ARRAY_T,	(void *)get_schedule_array_t,	(void *)add_schedule_array_t,		(void *)del_schedule_array_t },
#ifdef VLAN_CONFIG_SUPPORTED
	{ VLANCONFIG_ARRAY_T,	(void *)get_vlanconfig_array_t,	(void *)add_vlanconfig_array_t,		(void *)del_vlanconfig_array_t },
#endif
#ifdef WLAN_PROFILE
	{ PROFILE_ARRAY_T,	(void *)get_profile_array_t,	(void *)add_profile_array_t,		(void *)del_profile_array_t },
#endif
	{ -1,			NULL,			NULL,				NULL		}
};

const struct mib_tbl_operation *ysearch_mib_top(int type)
{
	const struct mib_tbl_operation *p;

	for (p = tops; p->_type != -1; p++) {
		if (p->_type == type)
			return p;
	}
	nm_errno = ENM_BADTYPE;
	return NULL;
}

int apmib_get_tblarray(int id, void *value, const struct mib *mib)
{
	int reqnum, n;
	const struct mib_tbl_operation *top;
	const struct mib *nib;
	char name[80];

	if (mib == NULL)
		return FALSE;

	top = ysearch_mib_top(mib->type);
	if (!top)
		return FALSE;

	nib = ysearch_mib_struct((id & MIB_ID_MASK) - 1);
	if (!nib) {
		nm_errno = ENM_NOMIB;
		return FALSE;
	}

	reqnum = (int)(*((unsigned char *)value));
	ynvram_name(name, sizeof(name), nib->name, nib->section);
	if (reqnum <= 0 || reqnum > strtol(nvram_safe_get(name), NULL, 0)) {
		nm_errno = ENM_OORNG;
		return FALSE;
	}
	ynvram_name(name, sizeof(name), mib->name, mib->section);
	n = strlen(name);
	snprintf(&name[n], sizeof(name) - n, "%d", reqnum);

	return top->_get(value, nvram_get(name), mib);
}

int apmib_add_tblarray(int id, void *value, const struct mib *mib, int num_id)
{
	const struct mib_tbl_operation *top;
	const struct mib *nib;

	if (mib == NULL)
		return FALSE;

	top = ysearch_mib_top(mib->type);
	if (!top)
		return FALSE;

	nib = ysearch_mib_struct(num_id);
	if (!nib) {
		nm_errno = ENM_NOMIB;
		return FALSE;
	}

	return top->_add(value, mib, nib);
}

int apmib_del_tblarray(int id, void *value, const struct mib *mib, int num_id, int flush)
{
	const struct mib_tbl_operation *top;
	const struct mib *nib;

	if (mib == NULL)
		return FALSE;

	top = ysearch_mib_top(mib->type);
	if (!top)
		return FALSE;

	nib = ysearch_mib_struct(num_id);
	if (!nib) {
		nm_errno = ENM_NOMIB;
		return FALSE;
	}

	return top->_del((flush) ? NULL : value, mib, nib);
}

int apmib_mod_tblentry(void)
{
	nm_errno = ENM_NOSYS;
	return FALSE;
}
