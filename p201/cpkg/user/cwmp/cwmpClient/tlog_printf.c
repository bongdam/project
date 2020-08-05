#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "tlog_printf.h"

#define TLOG_FILE_NAME "/tmp/tlog"
#define TLOG_SIZE (10*1024)
#define TLOG_NUM_FILE 2

static char _tl_fname[80]=TLOG_FILE_NAME;
static int  _tl_size=TLOG_SIZE;
static int  _tl_nfile=TLOG_NUM_FILE;
static int tlog_pid;

int tlog_init(char *fname, int sz, int nfile)
{
	tlog_pid = getpid();

	snprintf(_tl_fname, sizeof(_tl_fname), "%s", fname);
	if (sz > TLOG_SIZE)
		_tl_size = sz;
	if (nfile > TLOG_NUM_FILE)
		_tl_nfile = nfile;

	return 0;
}

static void file_rotate(char *fname, int sz, int nfile)
{
	int i;
	struct stat st;
	char fn1[80], fn2[80];

	if (stat(fname, &st)<0)
		st.st_size = 0;

	if (st.st_size < sz)
		return;

	// rotate file
	for (i=nfile-1; i>0; i--) {
		// i always greater than 0, (i-1) can be 0
		if (i==1)
			snprintf(fn1, sizeof(fn1), "%s", fname);
		else
			snprintf(fn1, sizeof(fn1), "%s.%d", fname, i-1);

		snprintf(fn2, sizeof(fn1), "%s.%d", fname, i);

		rename(fn1, fn2);
	}
}

static int print_time(FILE *fp)
{
	struct tm _tm;
	time_t t;

	time(&t);
	localtime_r(&t, &_tm);
	return fprintf(fp, "%02d/%02d %02d:%02d:%02d ", _tm.tm_mon+1, _tm.tm_mday, _tm.tm_hour, _tm.tm_min, _tm.tm_sec);
}

static int print_pid(FILE *fp)
{
	return fprintf(fp, "[%d] ", tlog_pid);
}

int tlog_printf(const char *fmt, ...)
{
	int ret=0;
	FILE *fp;
	va_list args;

	file_rotate(_tl_fname, _tl_size, _tl_nfile);

	fp = fopen(_tl_fname, "a");
	if (!fp)
		return 0;

	// time print
	ret += print_time(fp);
	
	// pid
	ret += print_pid(fp);

	// log print
	va_start(args, fmt);
	ret += vfprintf(fp, fmt, args);
	va_end(args);

	fclose(fp);
	return ret;
}

#include "glue.c"
