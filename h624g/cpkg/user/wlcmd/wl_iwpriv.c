#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>

#include <libytool.h>
#include "wlcmd.h"
#include "wl_iwpriv.h"

enum {
	MIB_UINT_TYPE,
	MIB_STR_TYPE,
};

typedef char * (*get_fn_t)(char *ifname, char *mibname, char *buf, int buf_sz);
typedef int (*set_fn_t)(char *ifname, char *mibname, char *val);

typedef struct _iwpriv_cmd_tbl {
	char *cmd;
	get_fn_t getfn;
	set_fn_t setfn;
	char * desc;
} iwpriv_cmd_tbl_t;

/*---------------------------------------------------------------------------*/
/*
 * 	# iwpriv wlan0 get_mib channel
 *	wlan0     get_mib:64  
 *
 *	# iwpriv wlan0 get_mib use40M  
 *	wlan0     get_mib:0  0  0  2  
 */ 
/*---------------------------------------------------------------------------*/
static int wl_iwpriv_set_channel(char *ifname, char *mibname, char *str);
static char *wl_iwpriv_get_channel(char *ifname, char *mibname, char *buf, int sz);
static char *wl_up(char *ifname, char *mibname, char *buf, int sz);
static char *wl_down(char *ifname, char *mibname, char *buf, int sz);
static char *wl_reset(char *ifname, char *mibname, char *buf, int sz);
static int wl_dummy_mibset(char *ifname, char *mibname, char *buf);

static iwpriv_cmd_tbl_t	iwpriv_cmd[] = {
	{"channel", wl_iwpriv_get_channel,	wl_iwpriv_set_channel, "set channel number"},
	{"up", wl_up,	wl_dummy_mibset, "\tup interface"},
	{"down", wl_down,	wl_dummy_mibset, "\tdown interface"},
	{"reset", wl_reset,	wl_dummy_mibset, "\treset interface"},
	{NULL, NULL, NULL, NULL},
};	

/*---------------------------------------------------------------------------*/
static int get_mib(char *ifname, char *mibname, char *working_buf, int bufsz, char **ag, int n)
{
	FILE *fp;
	char *p, file[40], target[40];
	int ret=0;
	
	snprintf(file, sizeof(file), "/tmp/iwpriv%u_%u", (unsigned int)getpid()%1000, (unsigned int)time(NULL)%1000);
	snprintf(target, sizeof(target),  ">%s", file);
	
	yexecl(target, "iwpriv %s get_mib %s", ifname, mibname);
	if ((fp = fopen(file, "r")) != NULL) {
		if (fgets(working_buf, bufsz, fp)!=NULL) {
			if ((p = strstr(working_buf, "get_mib:")) != NULL) {
				p += strlen("get_mib:");
				ret = ystrargs(p, ag, n, " ", 0);
			}
		}
		fclose(fp);
	}
	unlink(file);

	return (ret);
}

static int set_mib(char *ifname, char *mibname, int type, void *value)
{
	int ret = 0;

	if (type == MIB_UINT_TYPE) {
		yexecl(NULL, "iwpriv %s set_mib %s=%u", ifname, mibname, *((unsigned int *)value));
	} else if (type == MIB_STR_TYPE) {
		yexecl(NULL, "iwpriv %s set_mib %s=%s", ifname, mibname, (char *)value);
	} else {
		ret = -1;
	}

	return (ret);
}

/*---------------------------------------------------------------------------*/
static int wl_iwpriv_set_channel(char *ifname, char *mibname, char *str)
{
	char *p;
	unsigned int channel, use40m=0, f_2ndchoffset=0;
	
	channel = strtoul(str, &p, 10);
	if (p) {
		if (*p=='/') {
			if (!strcmp(p+1, "80"))
				use40m = 2;
			else if (!strcmp(p+1, "40"))
				use40m = 1;
			else if (!strcmp(p+1, "20"))
				use40m = 0;
			else
				return (-1);
		} else if (*p=='l' || *p=='L') {
			use40m = 1;
			f_2ndchoffset = 2;	/* above */
		} else if (*p=='u' || *p=='U') {
			use40m = 1;
			f_2ndchoffset = 1;	/* below */
		}
	}
	
	set_mib(ifname, "channel", MIB_UINT_TYPE, &channel);
	set_mib(ifname, "use40M", MIB_UINT_TYPE, &use40m);
	set_mib(ifname, "2ndchoffset", MIB_UINT_TYPE, &f_2ndchoffset);

	return 0;
}

static char *wl_iwpriv_get_channel(char *ifname, char *mibname, char *buf, int sz)
{
	char *ag[5], tmp[100];
	unsigned int chan, use40m=0, f_2ndchoffset=0;
	int ret;
	
	snprintf(buf, sz, "error");

	ret = get_mib(ifname, "channel", tmp, sizeof(tmp), ag, 5);
	if (ret<1)
		return(buf);
	chan = strtoul(ag[0], NULL, 10);

	ret = get_mib(ifname, "use40M", tmp, sizeof(tmp), ag, 5);
	if (ret<4)
		return(buf);
	use40m = strtoul(ag[3], NULL, 10);
	
	ret = get_mib(ifname, "2ndchoffset", tmp, sizeof(tmp), ag, 5);
	if (ret<1)
		return(buf);
	f_2ndchoffset = strtoul(ag[3], NULL, 10);

	if (use40m==2)
		snprintf(buf, sz, "%u/80", chan);
	else if (use40m==1) {
		if (f_2ndchoffset==2)
			snprintf(buf, sz, "%uL", chan);
		else if (f_2ndchoffset==1)
			snprintf(buf, sz, "%uU", chan);
		else
			snprintf(buf, sz, "%u/40", chan);
	} else {
		snprintf(buf, sz, "%u", chan);
	}
	
	return buf;
}

/*---------------------------------------------------------------------------*/
static char *wl_up(char *ifname, char *mibname, char *buf, int sz)
{
	yexecl(NULL, "ifconfig %s up", ifname);
	return (NULL);
}

static char *wl_down(char *ifname, char *mibname, char *buf, int sz)
{
	yexecl(NULL, "ifconfig %s down", ifname);
	return (NULL);
}

static char *wl_reset(char *ifname, char *mibname, char *buf, int sz)
{
	yexecl(NULL, "ifconfig %s down up", ifname);
	return (NULL);
}

static int wl_dummy_mibset(char *ifname, char *mibname, char *buf)
{
	return (0);
}
/*---------------------------------------------------------------------------*/
int wl_iwpriv_cmd_supported(char *mibname)
{
	iwpriv_cmd_tbl_t *tbl;
	
	for (tbl=iwpriv_cmd; tbl!=NULL && tbl->cmd!=NULL; tbl++) {
		if (!strcmp(tbl->cmd, mibname))
			return (1);
	}
	return (0);
}

int wl_iwpriv_cmd_table_print(FILE *fp)
{
	iwpriv_cmd_tbl_t *tbl;
	
	for (tbl=iwpriv_cmd; tbl!=NULL && tbl->cmd!=NULL; tbl++) {
		fprintf(fp, "%s:\t%s\n", tbl->cmd, tbl->desc);
	}
	return (0);
}

int wl_iwpriv_set_mib(char *ifname, char *mibname, char *val)
{
	iwpriv_cmd_tbl_t *tbl;
	
	for (tbl=iwpriv_cmd; tbl!=NULL && tbl->cmd!=NULL; tbl++) {
		if (!strcmp(tbl->cmd, mibname)) {
			return (tbl->setfn(ifname, mibname, val));
		}
	}
	return (0);
}

char *wl_iwpriv_get_mib(char *ifname, char *mibname, char *buf, int sz)
{
	iwpriv_cmd_tbl_t *tbl;
	
	for (tbl=iwpriv_cmd; tbl!=NULL && tbl->cmd!=NULL; tbl++) {
		if (!strcmp(tbl->cmd, mibname)) {
			return (tbl->getfn(ifname, mibname, buf, sz));
		}
	}
	return (NULL);
}
