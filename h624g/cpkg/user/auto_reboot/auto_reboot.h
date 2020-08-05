#ifndef __AUTO_REBOOT_H__
#define __AUTO_REBOOT_H__

#define AUTO_R_PRINT( ... ) \
	do { \
		if (auto_r_debug_enabled) \
			auto_r_dbg_printf( __VA_ARGS__ ); \
	} while(0)
#define AUTO_REBOOT_PID_FILE     "/var/run/auto_reboot.pid"
#define VALID_TIME(x) ((x) < 0 || (x) > 24)? -1: (x)
#define DEFAULT_UPTIME  7*24*60	//7DAY
#define DELAYMIN_DAY(x) ((x) == 6)? 1440*2: ((x) == 0)? 1440: 0
#define RED_COLOR              "\033[1;31m"
#define NORMAL_COLOR           "\033[0m"
#define LOOP_MAIN   1
#define MIN_TO_SEC(x)  (x) * 60
#define DEFAULT_DAY     7
#define CHECK_DAY(enable, m_day, s_day, e_day) (enable)?((m_day >= s_day && m_day <= e_day)? 1: 0):1
#define DEV_STATS_POS_RX_BYTE  0
#define DEV_STATS_POS_RX_CRC   1
#define TRAFFIC_TIME	300
#define AUTO_1DAY	86400

#define DEFAULT_TRAFFIC_BYTE    125000	//1000kbps

typedef struct {
	int auto_reboot_on_idle;	/* 0: self killed 1: run */
	int uptime;		/* day */
	int wan_port_idle;	/* 0: force 1: check traffic */
	int hour_range[2];	/* start:hour_range[0], end:hour_range[1] (0~23) */
	int min_range[2];		/* start:min_range[0], end:min_range[1] (0~59) */
} ldap_conf_t;

typedef struct {
	ldap_conf_t ldap_cnf;
	int check_day;		/* 0: not check 1: check */
	int start_day;
	int end_day;
	int bw_kbps;		/* wan trafic */
	int bw_monitor_min;	/* traffic monitor time */
	int sleep_ps_min;	/* default: 1 hour */
	int sleep_radom_min;	/* default: 10min */
	int wancrc;
} auto_r_conf_t;

typedef struct {
	int dv_auto_r_userforce;
	int dv_auto_r_enable;
	int dv_auto_r_dbg;
	int dv_auto_r_on_idle;
	char dv_auto_uptime[4];
	int dv_auto_wan_port_idle;
	char dv_auto_hour_range[12];
} auto_r_cfg;

typedef struct {
	char *name;
	char value[12];
} dv_variable;

#define WANIF "eth1"
#define LANIF "eth0"

int is_watching_tv_status();
char *get_auto_reboot_config(char *cfg_name);

#define SUN	0
#define MON	1
#define TUE	2
#define WED	3
#define THU	4
#define FRI	5
#define SAT	6

#endif
