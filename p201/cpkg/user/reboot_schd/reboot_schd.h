#ifndef __REBOOT_SCHD_H
#define __REBOOT_SCHD_H

typedef struct {
	u_int8_t day;
	u_int8_t hour;
	u_int8_t min;
	u_int8_t debug;
} reboot_schd;

enum {
	SUN,
	MON,
	TUE,
	WED,
	THU,
	FRI,
	SAT
};

#define SUN	0
#define MON	1
#define TUE	2
#define WED	3
#define THU	4
#define FRI	5
#define SAT	6

#define REBOOT_SCHD_PID_FILE	"/var/run/reboot_schd.pid"

#define ONE_DAY	86400

#define DEBUG_PRINT(fmt, args...) \
    do { \
        FILE *fp; \
        fp = fopen("/dev/console", "w"); \
        if (fp) { \
            fprintf(fp, fmt "\n", ## args); \
            fclose(fp); \
        } \
    } while(0);


#endif
