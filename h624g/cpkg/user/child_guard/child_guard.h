#ifndef __CHILD_GUARD_H__
#define __CHILD_GUARD_H__

#define CHILD_GUARD_PID_FILE     "/var/run/child_guard.pid"

#define CHILD_ALLOW 1
#define CHILD_DENY 2

#define CHILD_MAX 20
#define CHILD_1DAY 86400

#define SUN 0x01
#define MON 0x02
#define TUE 0x04
#define WED 0x08
#define THU 0x10
#define FRI 0x20
#define SAT 0x40

typedef struct {
	struct list_head list;
	int start_h;
	int start_m;
	int end_h;
	int end_m;
	int week;
} child_sta_t;

typedef struct {
	char mac[20];
	time_t s_time;
	time_t e_time;
	int allow;
	int radio;
	int run;
	child_sta_t sta;
} member_t;

#endif
