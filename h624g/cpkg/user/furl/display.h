/*
 * Display
 */

#ifndef __display_h__
#define __display_h__

#include <time.h>

#define DEFAULT_SW_MINUS_ONE 0
#define DEFAULT_SH_MINUS_ONE 0

#ifdef WIN32
typedef unsigned __int64 uint64;
typedef __int64 int64;
#define LLD "I64d"
#define LLU "I64u"
#else
#ifndef _TYPEDEFS_H_
typedef unsigned long long uint64;
typedef long long int64;
#endif
#define LLD "lld"
#define LLU "llu"
#endif

struct _display {
	time_t start_time;
	time_t total_time;
	time_t current_time;
	time_t elapsed_time;
	float percent_complete;
	int display_interval;
	int overtime_flag;
	int screen_width;
	int display_wait;
	int display_datacount;
	int display_throughput;
	int display_time;
	int display_elapsed_only;
	int display_percent;
	int display_bar;
	int display_summary;
	char bar_open_brace;
	char bar_close_brace;
	char bar_complete;
	char bar_incomplete;
	int total_display_percent;
	uint64 total_size;
	uint64 total_write;
	int total_size_known;
};

typedef struct _display display;
extern display d;

int displayInit(void);
int displayBegin(void);
int displayUpdate(void);
int displayEnd(void);

#endif
