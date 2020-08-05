#ifndef _aspvar_h_
#define _aspvar_h_

#include "boa.h"
#include "apmib.h"

enum {
    IF_BR = 0,
    IF_WAN,
    IF_ETC
};

enum {
    WLANVAR_NUM = 0,
    WLANVAR_IDX,
    WLANVAR_ETC
};

enum {
    VWLANVAR_NUM = 0,
    VWLANVAR_IDX,
    VWLANVAR_ETC
};

enum {
    MSSID_IDX = 0,
    MWLANVAR_ETC
};

struct aspvar {
	const char *name;
	int (*get)(request *, int, char **, struct aspvar *);
    long lparam;
    union {
        void *wparam;
        int warg1;
    };
    union {
    	void *wparam_def;         /* maybe used in pvar_getmib(), pvar_nvram() */
        int warg2;
    };
};

/* get handler */
int pvar_getmib(request * req, int argc, char **argv, struct aspvar *v);
int pvar_getnvram(request * req, int argc, char **argv, struct aspvar *v);
int pvar_uptime(request * req, int argc, char **argv, struct aspvar *v);
int pvar_ctime(request * req, int argc, char **argv, struct aspvar *v);
int pvar_printarg(request * req, int argc, char **argv, struct aspvar *v);
int pvar_return_zero(request *wp, int argc, char **argv, struct aspvar *v);

/* compare */
int pvar_compr(const struct aspvar *m1, const struct aspvar *m2);

/* instrument function */
int pwrite_puts(request *req, char *arg);
int pwrite_itoa(request *req, char *arg);
int pwrite_in_ntoa(request *req, char *arg);
int pwrite_in_ntoa2(request *req, char *arg);
int pwrite_etoa(request *req, char *arg);
int pwrite_etoa_without_colon(request *req, char *arg);
int pwrite_puts_webtrans(request *req, char *arg);
int pwrite_time_sec(request *req, char *arg);
int pwrite_time_sectomin(request *req, char *arg);
int pwrite_time_sectohour(request *req, char *arg);
int pwrite_time_sectoday(request *req, char *arg);

#endif	/* _aspvar_h_ */
