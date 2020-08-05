#include "aspvar.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <bcmnvram.h>

/*
   lparam : MIB Id
   wparam : stringify function pointer
 */
int pvar_getmib(request * req, int argc, char **argv, struct aspvar *v)
{
	/* Must have space enough */
	char buf[2048] = "";
	int (*stringify) (request *, char *);

	*(long *)buf = 0L;
	if (!apmib_get((int)v->lparam, (void *)buf)) {
        if (!(v->wparam_def))
    		return -1;
        else
            strncpy(buf, (char *)v->wparam_def, strlen((char *)v->wparam_def));
    }

	stringify = (int (*)(request *, char *))v->wparam;
	if (stringify)
		return stringify(req, buf);
	else
		return req_format_write(req, T("%s"), buf);
}

/*
   lparam : name
   wparam : default value, if not exists
 */
int pvar_getnvram(request * req, int argc, char **argv, struct aspvar *v)
{
	char *p = nvram_get((char *)v->lparam);
	int (*stringify) (request *, char *);
	if (p == NULL)
		p = (char *)v->wparam;
    if(v->wparam_def) {
	    stringify = (int (*)(request *, char *))v->wparam_def;
        stringify(req, p);
    } else
    	return req_format_write(req, T("%s"), p ? : "");
}

int pvar_uptime(request * req, int argc, char **argv, struct aspvar *v)
{
	struct sysinfo info;
	int sec, day, hr, mn;

	sysinfo(&info);
	sec = (unsigned long)info.uptime;
	day = sec / 86400;

	sec %= 86400;
	hr = sec / 3600;
	sec %= 3600;
	mn = sec / 60;
	sec %= 60;
	return req_format_write(req, "%dday:%dh:%dm:%ds", day, hr, mn, sec);
}

int pvar_ctime(request * req, int argc, char **argv, struct aspvar *v)
{
	time_t now;
	struct tm *ptm;

	time(&now);
	ptm = localtime(&now);
	if (!strcmp(argv[0], "year"))
		return req_format_write(req, "%d", (ptm->tm_year + 1900));
	else if (!strcmp(argv[0], "month"))
		return req_format_write(req, "%d", (ptm->tm_mon + 1));
	else if (!strcmp(argv[0], "day"))
		return req_format_write(req, "%d", (ptm->tm_mday));
	else if (!strcmp(argv[0], "hour"))
		return req_format_write(req, "%d", (ptm->tm_hour));
	else if (!strcmp(argv[0], "minute"))
		return req_format_write(req, "%d", (ptm->tm_min));
	else if (!strcmp(argv[0], "second"))
		return req_format_write(req, "%d", (ptm->tm_sec));
	return 0;
}

int pvar_printarg(request * req, int argc, char **argv, struct aspvar *v)
{
    /* Must have space enough */
	char buf[128];
	int (*stringify) (request *, char *);

	*(long *)buf = 0L;

    if (v->lparam)
        if (v->wparam) {
            //Do something
//            printf("%s: %lu\n", v->name, v->lparam);
            memcpy(buf, &(v->lparam), 128);
        } else {
            strcpy(buf, (char *)v->lparam);
//            printf("%s: %s\n", v->name, buf);
        }
    else
        return -1;

    stringify = (int (*)(request *, char *))v->wparam;
    if (stringify)
        return stringify(req, buf);
    else
        return req_format_write(req, T("%s"), buf);
}

int pvar_return_zero(request *wp, int argc, char **argv, struct aspvar *v)
{
    return 0;
}

int pvar_compr(const struct aspvar *m1, const struct aspvar *m2)
{
    return strcmp(m1->name, m2->name);
}
